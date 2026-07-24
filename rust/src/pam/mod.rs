// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! PAM module ("pam_glome.so") implementing GLOME Login authentication.
//!
//! Compiled in via the `pam` feature, which also builds this crate as a
//! `cdylib` so it can be loaded by Linux-PAM.

use nonstick::{
    pam_export, AuthnFlags, BaseFlags, ConversationAdapter, CredAction, ErrorCode, ModuleClient,
    PamModule, Result as PamResult,
};
use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

mod config;
mod login;

use config::Config;

/// Reports whether every byte in `buf` is zero (used to detect "not
/// configured" key material).
fn is_zeroed(buf: &[u8]) -> bool {
    buf.iter().fold(0u8, |acc, &b| acc | b) == 0
}

/// Matches `arg` against `key` (treating `-` in `key` as also matching `_`
/// in `arg`, mirroring PAM's usual dash/underscore option-name tolerance),
/// returning `Some(default)` for a bare `key` with no `=value`, `None` if
/// `arg` doesn't match `key` at all.
fn arg_value<'a>(arg: &'a str, key: &str, default: Option<&'a str>) -> Option<&'a str> {
    let arg_bytes = arg.as_bytes();
    let key_bytes = key.as_bytes();
    if arg_bytes.len() < key_bytes.len() {
        return None;
    }
    let matches = key_bytes
        .iter()
        .zip(arg_bytes)
        .all(|(&k, &a)| k == a || (k == b'-' && a == b'_'));
    if !matches {
        return None;
    }
    // Safe to slice: every byte compared above is ASCII (either equal to an
    // ASCII `key` byte, or `-`/`_`), so `key_bytes.len()` lands on a char
    // boundary.
    match &arg[key_bytes.len()..] {
        rest if rest.starts_with('=') => Some(&rest[1..]),
        "" => default,
        _ => None,
    }
}

// Maps a PAM module argument name to the config (section, key) it sets,
// along with the value implied by a bare flag with no `=value`.
const ARG_OPTIONS: &[(&str, Option<&str>, &str, &str)] = &[
    ("config-path", None, "default", "config-path"),
    ("key", None, "service", "key"),
    ("key-version", None, "service", "key-version"),
    ("prompt", None, "service", "prompt"),
    ("debug", Some("true"), "default", "verbose"),
    ("print-secrets", Some("true"), "default", "print-secrets"),
    ("host-id", None, "default", "host-id"),
    ("host-id-type", None, "default", "host-id-type"),
    ("ephemeral-key", None, "default", "ephemeral-key"),
    ("min-authcode-len", None, "default", "min-authcode-len"),
];

/// Applies each PAM module argument as a config option, logging (and
/// counting) any that don't match a known option or fail to apply.
fn parse_args<M: ModuleClient>(handle: &M, config: &mut Config, args: &[String]) -> Result<(), ()> {
    let mut errors = 0;
    for arg in args {
        let assignment = ARG_OPTIONS
            .iter()
            .find_map(|&(name, default, section, key)| {
                arg_value(arg, name, default).map(|val| (section, key, val))
            });

        match assignment {
            None => {
                nonstick::error!(handle, "invalid option {arg}");
                errors += 1;
            }
            Some((section, key, val)) => {
                if let Err(e) = config::assign_config_option(config, section, key, val) {
                    nonstick::error!(handle, "failed to set config option '{arg}': {e}");
                    errors += 1;
                }
            }
        }
    }
    if errors > 0 {
        Err(())
    } else {
        Ok(())
    }
}

// OpenSSH provides this fake password when login is not allowed (e.g. due
// to PermitRootLogin=no); see
// https://github.com/openssh/openssh-portable/commit/283b97. OpenSSH pads
// it out to the expected password length by repeating the pattern, hence
// the cyclic comparison below.
const FAKE_PASSWORD: &[u8] = b"\x08\n\r\x7fINCORRECT";

/// Reports whether `token` is OpenSSH's fake password. Note that an empty
/// `token` is considered "fake" (the comparison loop that would disprove
/// it never runs).
fn is_fake_password(token: &[u8]) -> bool {
    let mut is_fake = true;
    for (i, &b) in token.iter().enumerate() {
        is_fake &= b == FAKE_PASSWORD[i % FAKE_PASSWORD.len()];
    }
    is_fake
}

/// Displays the challenge, retrieves the user's authtok (rejecting
/// OpenSSH's fake password used when login is not allowed), and validates
/// the response.
fn authenticate_with_config<M: ModuleClient>(
    handle: &mut M,
    config: &mut Config,
) -> Result<(), String> {
    let challenge = login::build_challenge(config)?;

    if config.verbose {
        nonstick::debug!(handle, "login message: {}", challenge.message);
    }

    handle.info_msg(challenge.prompt.as_str());

    let token = handle
        .authtok(None)
        .map_err(|e| format!("pam-get-authtok: {e}"))?;
    let token_bytes = token.as_bytes();

    if token_bytes.len() > challenge.authcode_encoded.len() {
        return Err("pam-authtok-size".to_string());
    }

    if is_fake_password(token_bytes) {
        return Err("pam-authtok-openssh-no-login".to_string());
    }

    if config.insecure {
        nonstick::debug!(handle, "user input: {}", token.to_string_lossy());
        nonstick::debug!(handle, "expect input: {}", challenge.authcode_encoded);
    }

    let username = config.username.as_deref().unwrap_or("");
    let auth_delay_sec = config.auth_delay_sec;
    let delay = || {
        if auth_delay_sec > 0 {
            std::thread::sleep(Duration::from_secs(auth_delay_sec.into()));
        }
    };

    match login::verify_authcode(&challenge, token_bytes, config.min_authcode_len, delay) {
        Ok(()) => Ok(()),
        Err(login::AuthcodeError::MinLenTooLong {
            min_authcode_len, ..
        }) => {
            nonstick::info!(
                handle,
                "minimum authcode too long: {min_authcode_len} bytes ({username})"
            );
            handle.error_msg(format!(
                "Minimum input too long: expected at most {min_authcode_len} characters.\n"
            ));
            Err("authcode-length".to_string())
        }
        Err(login::AuthcodeError::TooShort { min_len, got }) => {
            nonstick::info!(handle, "authcode too short: {got} bytes ({username})");
            handle.error_msg(format!(
                "Input too short: expected at least {min_len} characters, got {got}.\n"
            ));
            Err("authcode-length".to_string())
        }
        Err(login::AuthcodeError::TooLong { full_len, got }) => {
            nonstick::info!(handle, "authcode too long: {got} bytes ({username})");
            handle.error_msg(format!(
                "Input too long: expected at most {full_len} characters, got {got}.\n"
            ));
            Err("authcode-length".to_string())
        }
        Err(login::AuthcodeError::Invalid) => {
            nonstick::warn!(handle, "authcode rejected ({username})");
            handle.error_msg("Invalid authorization code.\n");
            Err("authcode-invalid".to_string())
        }
    }
}

struct Glome;

pam_export!(Glome);

impl<M: ModuleClient> PamModule<M> for Glome {
    /// Parses config (module arguments, then the config file, then module
    /// arguments again as overrides), looks up the username, and runs the
    /// GLOME Login challenge/response authentication flow.
    fn authenticate(handle: &mut M, args: Vec<&CStr>, _flags: AuthnFlags) -> PamResult<()> {
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        // Parse arguments to initialize the config path.
        let mut config = Config::default();
        parse_args(handle, &mut config, &args).map_err(|()| {
            nonstick::error!(handle, "failed to parse pam module arguments");
            ErrorCode::AuthenticationError
        })?;

        // Reset config while preserving the config path.
        let config_path = config.config_path.take();
        config = Config {
            config_path,
            ..Config::default()
        };

        // Read configuration file.
        config::parse_config_file(&mut config).map_err(|e| {
            nonstick::error!(handle, "failed to read config file: {e}");
            ErrorCode::AuthenticationError
        })?;

        // Parse arguments again to override config values.
        parse_args(handle, &mut config, &args).map_err(|()| {
            nonstick::error!(handle, "failed to parse pam module arguments");
            ErrorCode::AuthenticationError
        })?;

        let username = handle
            .username(None)
            .ok()
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                nonstick::error!(handle, "failed to get username");
                ErrorCode::AuthenticationError
            })?;
        config.username = Some(username.to_string_lossy().into_owned());

        authenticate_with_config(handle, &mut config).map_err(|e| {
            nonstick::error!(
                handle,
                "failed to authenticate user '{}': {e}",
                config.username.as_deref().unwrap_or("")
            );
            ErrorCode::AuthenticationError
        })?;

        if config.verbose {
            nonstick::error!(
                handle,
                "authenticated user '{}'",
                config.username.as_deref().unwrap_or("")
            );
        }
        Ok(())
    }

    /// This module does not generate any user credentials, so it just
    /// reports success (`Ignore`, the default for unimplemented hooks, is
    /// deliberately not used here).
    fn set_credentials(
        _handle: &mut M,
        _args: Vec<&CStr>,
        _action: CredAction,
        _flags: BaseFlags,
    ) -> PamResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nonstick::conv::Exchange;
    use nonstick::items::{Items, ItemsMut};
    use nonstick::logging::{Level, Location, Logger};
    use nonstick::{Conversation, EnvironMap, EnvironMapMut, PamShared};
    use std::any::Any;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ffi::{OsStr, OsString};
    use std::fmt;
    use std::os::unix::ffi::OsStringExt as _;

    /// A minimal, in-memory fake of a PAM handle, for exercising
    /// `pam` module code without a real PAM stack. Only the pieces
    /// `authenticate`/`authenticate_with_config`/`parse_args` actually touch
    /// (logging, info/error messages, username, authtok) hold real state;
    /// everything else is a harmless stub, since `ModuleClient`'s full trait
    /// surface must be implemented regardless of what's exercised.
    #[derive(Default)]
    struct FakeClient {
        username: Option<OsString>,
        authtok: Option<OsString>,
        info_msgs: RefCell<Vec<String>>,
        error_msgs: RefCell<Vec<String>>,
        logs: RefCell<Vec<String>>,
        module_data: HashMap<String, Box<dyn Any>>,
    }

    impl Logger for FakeClient {
        fn log(&self, _level: Level, _loc: Location<'_>, entry: fmt::Arguments) {
            self.logs.borrow_mut().push(entry.to_string());
        }
    }

    impl Conversation for FakeClient {
        fn communicate(&self, messages: &[Exchange]) {
            for msg in messages {
                match msg {
                    Exchange::Info(m) => {
                        self.info_msgs
                            .borrow_mut()
                            .push(m.question().to_string_lossy().into_owned());
                        m.set_answer(Ok(()));
                    }
                    Exchange::Error(m) => {
                        self.error_msgs
                            .borrow_mut()
                            .push(m.question().to_string_lossy().into_owned());
                        m.set_answer(Ok(()));
                    }
                    other => other.set_error(ErrorCode::ConversationError),
                }
            }
        }
    }

    /// A no-op stand-in for the environment/Items maps, which
    /// `authenticate`/`authenticate_with_config`/`parse_args` never touch.
    struct NullPamData;

    impl EnvironMap<'_> for NullPamData {
        fn get(&self, _key: impl AsRef<OsStr>) -> Option<OsString> {
            None
        }
        fn iter(&self) -> impl Iterator<Item = (OsString, OsString)> {
            std::iter::empty()
        }
    }
    impl EnvironMapMut<'_> for NullPamData {
        fn insert(&mut self, _key: impl AsRef<OsStr>, _val: impl AsRef<OsStr>) -> Option<OsString> {
            None
        }
        fn remove(&mut self, _key: impl AsRef<OsStr>) -> Option<OsString> {
            None
        }
    }
    impl Items<'_> for NullPamData {
        fn user(&self) -> PamResult<Option<OsString>> {
            Ok(None)
        }
        fn remote_user(&self) -> PamResult<Option<OsString>> {
            Ok(None)
        }
        fn remote_host(&self) -> PamResult<Option<OsString>> {
            Ok(None)
        }
        fn service(&self) -> PamResult<Option<OsString>> {
            Ok(None)
        }
        fn user_prompt(&self) -> PamResult<Option<OsString>> {
            Ok(None)
        }
        fn tty_name(&self) -> PamResult<Option<OsString>> {
            Ok(None)
        }
    }
    impl ItemsMut<'_> for NullPamData {
        fn set_user(&mut self, _value: Option<&OsStr>) -> PamResult<()> {
            Ok(())
        }
        fn set_service(&mut self, _value: Option<&OsStr>) -> PamResult<()> {
            Ok(())
        }
        fn set_user_prompt(&mut self, _value: Option<&OsStr>) -> PamResult<()> {
            Ok(())
        }
        fn set_tty_name(&mut self, _value: Option<&OsStr>) -> PamResult<()> {
            Ok(())
        }
        fn set_remote_user(&mut self, _value: Option<&OsStr>) -> PamResult<()> {
            Ok(())
        }
        fn set_remote_host(&mut self, _value: Option<&OsStr>) -> PamResult<()> {
            Ok(())
        }
        fn set_authtok(&mut self, _value: Option<&OsStr>) -> PamResult<()> {
            Ok(())
        }
        fn set_old_authtok(&mut self, _value: Option<&OsStr>) -> PamResult<()> {
            Ok(())
        }
    }

    impl PamShared for FakeClient {
        fn environ(&self) -> impl EnvironMap {
            NullPamData
        }
        fn environ_mut(&mut self) -> impl EnvironMapMut {
            NullPamData
        }
        fn items(&self) -> impl Items {
            NullPamData
        }
        fn items_mut(&mut self) -> impl ItemsMut {
            NullPamData
        }
    }

    impl ModuleClient for FakeClient {
        fn username(&mut self, _prompt: Option<&OsStr>) -> PamResult<OsString> {
            self.username.clone().ok_or(ErrorCode::ConversationError)
        }
        fn authtok(&mut self, _prompt: Option<&OsStr>) -> PamResult<OsString> {
            self.authtok.clone().ok_or(ErrorCode::ConversationError)
        }
        fn old_authtok(&mut self, _prompt: Option<&OsStr>) -> PamResult<OsString> {
            Err(ErrorCode::ConversationError)
        }
        fn get_module_data<T: 'static>(&self, key: &str) -> Option<&T> {
            self.module_data
                .get(key)
                .and_then(|v| v.downcast_ref::<T>())
        }
        fn set_module_data<T: 'static>(&mut self, key: &str, data: T) -> PamResult<()> {
            self.module_data.insert(key.to_string(), Box::new(data));
            Ok(())
        }
        fn authtok_item(&self) -> PamResult<Option<OsString>> {
            Ok(self.authtok.clone())
        }
        fn old_authtok_item(&self) -> PamResult<Option<OsString>> {
            Ok(None)
        }
    }

    /// A `Config` with everything `authenticate_with_config` needs to
    /// successfully build a challenge. The keys are arbitrary fixed bytes
    /// (not derived from any real secret) purely to exercise the code path
    /// deterministically.
    fn auth_test_config() -> Config {
        Config {
            service_key: [0x11; 32],
            secret_key: [0x22; 32],
            username: Some("root".to_string()),
            host_id: Some("myhost".to_string()),
            host_id_type: Some("mytype".to_string()),
            ..Config::default()
        }
    }

    #[test]
    fn test_authenticate_with_config_accepts_correct_authcode() {
        let mut config = auth_test_config();
        let challenge = login::build_challenge(&mut config).expect("should build");

        let mut handle = FakeClient {
            authtok: Some(OsString::from(challenge.authcode_encoded.clone())),
            ..Default::default()
        };

        assert!(authenticate_with_config(&mut handle, &mut config).is_ok());
        assert_eq!(handle.info_msgs.borrow().len(), 1);
    }

    #[test]
    fn test_authenticate_with_config_rejects_wrong_authcode() {
        let mut config = auth_test_config();
        let mut handle = FakeClient {
            authtok: Some(OsString::from("totally-wrong-code")),
            ..Default::default()
        };

        assert_eq!(
            authenticate_with_config(&mut handle, &mut config),
            Err("authcode-invalid".to_string())
        );
    }

    #[test]
    fn test_authenticate_with_config_rejects_openssh_fake_password() {
        let mut config = auth_test_config();
        let mut handle = FakeClient {
            authtok: Some(OsString::from_vec(FAKE_PASSWORD.to_vec())),
            ..Default::default()
        };

        assert_eq!(
            authenticate_with_config(&mut handle, &mut config),
            Err("pam-authtok-openssh-no-login".to_string())
        );
    }

    #[test]
    fn test_authenticate_with_config_rejects_oversized_authtok() {
        let mut config = auth_test_config();
        let challenge = login::build_challenge(&mut config).expect("should build");
        let oversized = "A".repeat(challenge.authcode_encoded.len() + 1);
        let mut handle = FakeClient {
            authtok: Some(OsString::from(oversized)),
            ..Default::default()
        };

        assert_eq!(
            authenticate_with_config(&mut handle, &mut config),
            Err("pam-authtok-size".to_string())
        );
    }

    #[test]
    fn test_parse_args_applies_known_options() {
        let handle = FakeClient::default();
        let mut config = Config::default();
        let args = vec!["debug".to_string(), "key-version=5".to_string()];

        assert!(parse_args(&handle, &mut config, &args).is_ok());
        assert!(config.verbose);
        assert_eq!(config.service_key_id, 5);
    }

    #[test]
    fn test_parse_args_reports_unrecognized_option() {
        let handle = FakeClient::default();
        let mut config = Config::default();
        let args = vec!["not-a-real-option".to_string()];

        assert!(parse_args(&handle, &mut config, &args).is_err());
        assert_eq!(handle.logs.borrow().len(), 1);
    }

    #[test]
    fn test_parse_args_reports_option_that_fails_to_apply() {
        let handle = FakeClient::default();
        let mut config = Config::default();
        // key-version must be in 0..=127.
        let args = vec!["key-version=200".to_string()];

        assert!(parse_args(&handle, &mut config, &args).is_err());
        assert_eq!(handle.logs.borrow().len(), 1);
    }

    #[test]
    fn test_arg_value_bare_flag_uses_default() {
        assert_eq!(arg_value("debug", "debug", Some("true")), Some("true"));
    }

    #[test]
    fn test_arg_value_with_equals() {
        assert_eq!(arg_value("key=abcd", "key", None), Some("abcd"));
        assert_eq!(arg_value("key=", "key", None), Some(""));
    }

    #[test]
    fn test_arg_value_underscore_in_arg_matches_dash_in_key() {
        assert_eq!(
            arg_value("config_path=/etc/foo", "config-path", None),
            Some("/etc/foo")
        );
        assert_eq!(
            arg_value("min_authcode_len=10", "min-authcode-len", None),
            Some("10")
        );
    }

    #[test]
    fn test_arg_value_dash_in_arg_does_not_match_non_dash_key_char() {
        // The tolerance only goes one way: '-' in the key may match '_' in
        // the arg, but not the reverse.
        assert_eq!(arg_value("ke-", "key", None), None);
    }

    #[test]
    fn test_arg_value_no_match() {
        assert_eq!(arg_value("keyword=x", "key", None), None);
        assert_eq!(arg_value("ke", "key", None), None);
        assert_eq!(arg_value("unrelated", "key", None), None);
    }

    #[test]
    fn test_arg_value_bare_flag_without_default_is_no_match() {
        assert_eq!(arg_value("key", "key", None), None);
    }

    #[test]
    fn test_is_fake_password_exact_match() {
        assert!(is_fake_password(FAKE_PASSWORD));
    }

    #[test]
    fn test_is_fake_password_prefix() {
        assert!(is_fake_password(b"\x08\n\r\x7f"));
    }

    #[test]
    fn test_is_fake_password_repeated_pattern() {
        // OpenSSH pads the fake password out to the requested length by
        // repeating the pattern.
        let doubled: Vec<u8> = FAKE_PASSWORD.iter().chain(FAKE_PASSWORD).copied().collect();
        assert!(is_fake_password(&doubled));
    }

    #[test]
    fn test_is_fake_password_empty_is_considered_fake() {
        // The comparison loop never runs, so `is_fake` stays true.
        assert!(is_fake_password(b""));
    }

    #[test]
    fn test_is_fake_password_real_authcode_is_not_fake() {
        assert!(!is_fake_password(b"Xt-yvSPnAz"));
    }
}
