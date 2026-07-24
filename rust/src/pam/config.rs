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

//! Configuration for the GLOME PAM module.
//!
//! The on-disk config file format and PAM module argument names are kept
//! identical to existing deployments so they keep working unchanged.

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use std::fs;

use super::is_zeroed;

pub(super) const DEFAULT_LOGIN_PATH: &str = "/bin/login";
pub(super) const DEFAULT_PROMPT: &str = "GLOME: ";
pub(super) const DEFAULT_AUTH_DELAY: u32 = 1;
pub(super) const DEFAULT_INPUT_TIMEOUT: u32 = 180;

// Set at compile time from the `SYSCONFDIR` environment variable (see
// `build.rs`), defaulting to `/etc` if unset.
const DEFAULT_CONFIG_FILE: &str = concat!(env!("SYSCONFDIR"), "/glome/config");

/// GLOME PAM module configuration, populated from PAM module arguments and
/// the on-disk config file.
#[derive(Debug)]
pub(super) struct Config {
    pub(super) verbose: bool,
    pub(super) insecure: bool,
    pub(super) syslog: bool,
    pub(super) username: Option<String>,
    pub(super) config_path: Option<String>,
    pub(super) login_path: String,
    pub(super) prompt: String,
    pub(super) auth_delay_sec: u32,
    pub(super) input_timeout_sec: u32,
    pub(super) min_authcode_len: u32,
    pub(super) service_key: [u8; 32],
    pub(super) service_key_id: u8,
    pub(super) secret_key: [u8; 32],
    pub(super) host_id: Option<String>,
    pub(super) host_id_type: Option<String>,
}

impl Default for Config {
    /// The configuration used before any PAM module arguments or config
    /// file have been applied.
    fn default() -> Self {
        Self {
            verbose: false,
            insecure: false,
            syslog: true,
            username: None,
            config_path: None,
            login_path: DEFAULT_LOGIN_PATH.to_string(),
            prompt: DEFAULT_PROMPT.to_string(),
            auth_delay_sec: DEFAULT_AUTH_DELAY,
            input_timeout_sec: DEFAULT_INPUT_TIMEOUT,
            min_authcode_len: 0,
            service_key: [0; 32],
            service_key_id: 0,
            secret_key: [0; 32],
            host_id: None,
            host_id_type: None,
        }
    }
}

/// Decodes `input` (an optionally `0x`-prefixed hex string) into `dst`,
/// requiring it to decode to exactly `dst.len()` bytes.
fn decode_hex(dst: &mut [u8], input: &str) -> Result<(), String> {
    let stripped = if input.len() > 2 && input.starts_with("0x") {
        &input[2..]
    } else {
        input
    };
    if stripped.len() != dst.len() * 2 {
        return Err(format!(
            "hex-encoded key must have exactly {} characters (got {})",
            dst.len() * 2,
            stripped.len()
        ));
    }
    for (i, byte) in dst.iter_mut().enumerate() {
        let chunk = stripped
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| format!("parsing byte {i} as hex: input is not valid ASCII"))?;
        *byte = u8::from_str_radix(chunk, 16)
            .map_err(|_| format!("parsing byte {i} ('{chunk}') as hex"))?;
    }
    Ok(())
}

/// Once a key has been set to a non-zero value, later assignments are
/// silently ignored. In practice this means a service/ephemeral key from
/// the config file takes precedence over one supplied via PAM module
/// arguments, since the config file is parsed after the first
/// (config-path-only) argument pass but before the second (override) pass.
fn assign_key(dest: &mut [u8; 32], val: &str) -> Result<(), String> {
    if is_zeroed(dest) {
        decode_hex(dest, val)?;
    }
    Ok(())
}

/// Parses an unsigned integer the way `strtoul(val, &end, 0)` does: a `0x`/
/// `0X` prefix means hex, a leading `0` (with more digits) means octal,
/// otherwise decimal.
fn parse_uint(val: &str) -> Result<u32, String> {
    let (radix, digits) = if let Some(h) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X"))
    {
        (16, h)
    } else if val.len() > 1 && val.starts_with('0') {
        (8, &val[1..])
    } else {
        (10, val)
    };
    if digits.is_empty() {
        return Err(format!("invalid value for option: {val}"));
    }
    u32::from_str_radix(digits, radix).map_err(|_| format!("invalid value for option: {val}"))
}

/// Parses a key-version index, which must be in `0..=127`.
fn parse_key_version(val: &str) -> Result<u8, String> {
    let n = parse_uint(val)?;
    if n > 127 {
        return Err(format!("'{val}' is not a valid key version (0..127)"));
    }
    Ok(n as u8)
}

/// Parses a case-insensitive boolean value (`1`/`true`/`yes`/`on` or
/// `0`/`false`/`no`/`off`).
fn parse_bool(val: &str) -> Result<bool, String> {
    if ["1", "true", "yes", "on"]
        .iter()
        .any(|s| val.eq_ignore_ascii_case(s))
    {
        Ok(true)
    } else if ["0", "false", "no", "off"]
        .iter()
        .any(|s| val.eq_ignore_ascii_case(s))
    {
        Ok(false)
    } else {
        Err(format!("unrecognized boolean value: {val}"))
    }
}

/// Parses a `glome-v1 <base64url-key> [comment]`-formatted public key into
/// `dst`.
fn parse_public_key(encoded: &str, dst: &mut [u8; 32]) -> Result<(), String> {
    const PREFIX: &str = "glome-v1";
    if !encoded.starts_with(PREFIX) {
        return Err(format!("unsupported public key encoding: {encoded}"));
    }
    let rest = encoded[PREFIX.len()..].trim_start_matches([' ', '\t']);
    // Truncate at the first non-printable/space character to allow for
    // appended comments (e.g. "glome-v1 <key> user@host").
    let end = rest
        .find(|c: char| !c.is_ascii_graphic())
        .unwrap_or(rest.len());
    let decoded = URL_SAFE
        .decode(&rest[..end])
        .map_err(|e| format!("decoding public-key: {e}"))?;
    if decoded.len() != dst.len() {
        return Err(format!(
            "public key decoded to {} bytes, expected {}",
            decoded.len(),
            dst.len()
        ));
    }
    dst.copy_from_slice(&decoded);
    Ok(())
}

/// Applies a `key = val` option from the `[default]` config section (or an
/// equivalent PAM module argument).
fn assign_default_option(config: &mut Config, key: &str, val: &str) -> Result<(), String> {
    match key {
        "auth-delay" => config.auth_delay_sec = parse_uint(val)?,
        "input-timeout" | "timeout" => config.input_timeout_sec = parse_uint(val)?,
        "config-path" => config.config_path = Some(val.to_string()),
        "ephemeral-key" => assign_key(&mut config.secret_key, val)?,
        "min-authcode-len" => config.min_authcode_len = parse_uint(val)?,
        "host-id" => config.host_id = Some(val.to_string()),
        "host-id-type" => config.host_id_type = Some(val.to_string()),
        "login-path" => config.login_path = val.to_string(),
        "disable-syslog" => config.syslog = !parse_bool(val)?,
        "print-secrets" => config.insecure = parse_bool(val)?,
        "verbose" => config.verbose = parse_bool(val)?,
        _ => return Err(format!("unrecognized default option: {key}")),
    }
    Ok(())
}

/// Applies a `key = val` option from the `[service]` config section (or an
/// equivalent PAM module argument).
fn assign_service_option(config: &mut Config, key: &str, val: &str) -> Result<(), String> {
    match key {
        "key" => assign_key(&mut config.service_key, val)?,
        "key-version" => config.service_key_id = parse_key_version(val)?,
        // `url-prefix` is kept only for backwards compatibility.
        // TODO: remove in the 1.0 release.
        "url-prefix" => config.prompt = format!("{val}/"),
        "prompt" => config.prompt = val.to_string(),
        "public-key" => parse_public_key(val, &mut config.service_key)?,
        _ => return Err(format!("unrecognized service option: {key}")),
    }
    Ok(())
}

/// Applies a `key = val` option from the given config section (`"default"`
/// or `"service"`).
pub(super) fn assign_config_option(
    config: &mut Config,
    section: &str,
    key: &str,
    val: &str,
) -> Result<(), String> {
    match section {
        "service" => assign_service_option(config, key, val),
        "default" => assign_default_option(config, key, val),
        _ => Err(format!("config section not recognized: {section}")),
    }
}

/// Reports whether `s` is a valid config key or section name (alphanumeric,
/// `_`, and `-` only).
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Reports whether `line` is blank (whitespace-only).
fn is_empty_line(line: &str) -> bool {
    line.trim().is_empty()
}

/// Reports whether `line` is a comment line. Comments/sections must start
/// in column 0; leading whitespace before `#`/`;`/`[` is not stripped and
/// instead falls through to key/value parsing (and is rejected there).
fn is_comment(line: &str) -> bool {
    line.starts_with('#') || line.starts_with(';')
}

/// Parses a `[section]` line, returning the section name.
fn parse_section_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let end = rest.find(']')?;
    let (name, trailing) = (&rest[..end], &rest[end + 1..]);
    if !trailing.trim().is_empty() || !is_name(name) {
        return None;
    }
    Some(name)
}

/// Parses a `key = val` (or `key val`) line, returning the key and value.
fn parse_key_value(line: &str) -> Option<(&str, &str)> {
    let key_end = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = &line[..key_end];
    let after_eq = line[key_end..].trim_start().strip_prefix('=')?.trim_start();
    if after_eq.is_empty() || !is_name(key) {
        return None;
    }
    Some((key, after_eq.trim_end()))
}

/// The default config file is optional (a missing file is not an error),
/// but an explicitly configured one must exist.
pub(super) fn parse_config_file(config: &mut Config) -> Result<(), String> {
    let required = config.config_path.is_some();
    let path = config
        .config_path
        .get_or_insert_with(|| DEFAULT_CONFIG_FILE.to_string())
        .clone();

    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) => {
            return if required {
                Err(format!("config file could not be opened: {e}"))
            } else {
                Ok(())
            };
        }
    };

    let mut section: Option<String> = None;
    for (i, line) in content.lines().enumerate() {
        let line_no = i + 1;
        if is_empty_line(line) || is_comment(line) {
            continue;
        }
        if line.starts_with('[') {
            let name = parse_section_name(line).ok_or_else(|| {
                format!("config file parsing failed in line {line_no} (bad section name)")
            })?;
            section = Some(name.to_string());
        } else {
            let (key, val) = parse_key_value(line).ok_or_else(|| {
                format!("config file parsing failed in line {line_no} (bad key/value)")
            })?;
            assign_config_option(config, section.as_deref().unwrap_or("default"), key, val)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const ENCODED_PUBLIC_KEY: &str = "glome-v1 aqA9yqe1RXoOT6HrmCbF40wVUhYp50FYZR9q8_X5KF4=";
    const DECODED_PUBLIC_KEY: [u8; 32] = [
        0x6a, 0xa0, 0x3d, 0xca, 0xa7, 0xb5, 0x45, 0x7a, 0x0e, 0x4f, 0xa1, 0xeb, 0x98, 0x26, 0xc5,
        0xe3, 0x4c, 0x15, 0x52, 0x16, 0x29, 0xe7, 0x41, 0x58, 0x65, 0x1f, 0x6a, 0xf3, 0xf5, 0xf9,
        0x28, 0x5e,
    ];

    #[test]
    fn test_parse_public_key() {
        let mut decoded = [0u8; 32];
        parse_public_key(ENCODED_PUBLIC_KEY, &mut decoded).expect("should decode");
        assert_eq!(decoded, DECODED_PUBLIC_KEY);

        assert!(parse_public_key(
            "glome-group1-md5 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
            &mut decoded
        )
        .is_err());
        assert!(parse_public_key("glome-v1 QUFBQUFBQUFB", &mut decoded).is_err());

        let mut decoded = [0u8; 32];
        let extra_chars = "glome-v1 \t aqA9yqe1RXoOT6HrmCbF40wVUhYp50FYZR9q8_X5KF4= root@localhost";
        parse_public_key(extra_chars, &mut decoded).expect("should decode with trailing comment");
        assert_eq!(decoded, DECODED_PUBLIC_KEY);
    }

    fn temp_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("should create temp file");
        f.write_all(content.as_bytes())
            .expect("should write temp file");
        f
    }

    fn assert_common_fields(config: &Config) {
        assert_eq!(config.auth_delay_sec, 7);
        assert_eq!(config.min_authcode_len, 15);
        assert_eq!(config.input_timeout_sec, 321);
        assert_eq!(config.login_path, "/bin/true");
        assert_eq!(config.host_id.as_deref(), Some("my-host"));
        assert_eq!(config.host_id_type.as_deref(), Some("hostname"));
        assert!(config.verbose);
        assert!(!config.syslog);
        assert!(!config.insecure);
        assert_eq!(config.service_key, DECODED_PUBLIC_KEY);
        assert_eq!(config.service_key_id, 42);
    }

    #[test]
    fn test_parse_config_file() {
        let file = temp_config(
            "auth-delay = 7\n\
             min-authcode-len = 15\n\
             input-timeout = 321\n\
             host-id = my-host\n\
             host-id-type = hostname\n\
             login-path = /bin/true\n\
             disable-syslog = yes\n\
             print-secrets = 0\n\
             verbose = true\n\
             \n\
             [service]\n\
             # a comment\n\
             public-key = glome-v1 aqA9yqe1RXoOT6HrmCbF40wVUhYp50FYZR9q8_X5KF4=\n\
             key-version = 42\n\
             prompt = glome://\n",
        );

        let mut config = Config {
            config_path: Some(file.path().to_str().unwrap().to_string()),
            ..Default::default()
        };
        parse_config_file(&mut config).expect("should parse");

        assert_common_fields(&config);
        assert_eq!(config.prompt, "glome://");
    }

    #[test]
    fn test_parse_config_file_url_prefix() {
        let file = temp_config(
            "auth-delay = 7\n\
             min-authcode-len = 15\n\
             input-timeout = 321\n\
             host-id = my-host\n\
             host-id-type = hostname\n\
             login-path = /bin/true\n\
             disable-syslog = yes\n\
             print-secrets = 0\n\
             verbose = true\n\
             \n\
             [service]\n\
             public-key = glome-v1 aqA9yqe1RXoOT6HrmCbF40wVUhYp50FYZR9q8_X5KF4=\n\
             key-version = 42\n\
             url-prefix = glome:/\n",
        );

        let mut config = Config {
            config_path: Some(file.path().to_str().unwrap().to_string()),
            ..Default::default()
        };
        parse_config_file(&mut config).expect("should parse");

        assert_common_fields(&config);
        assert_eq!(config.prompt, "glome://");
    }

    #[test]
    fn test_missing_default_config_is_not_an_error() {
        let mut config = Config::default();
        assert!(config.config_path.is_none());
        parse_config_file(&mut config).expect("missing default config should be ignored");
    }

    #[test]
    fn test_missing_explicit_config_is_an_error() {
        let mut config = Config {
            config_path: Some("/nonexistent/path/to/glome/config".to_string()),
            ..Default::default()
        };
        assert!(parse_config_file(&mut config).is_err());
    }

    #[test]
    fn test_key_option_first_set_wins() {
        let mut config = Config::default();
        assign_config_option(&mut config, "service", "key", &"11".repeat(32)).unwrap();
        assign_config_option(&mut config, "service", "key", &"22".repeat(32)).unwrap();
        assert_eq!(config.service_key, [0x11; 32]);
    }

    #[test]
    fn test_public_key_option_always_overwrites() {
        let mut config = Config::default();
        assign_config_option(&mut config, "service", "key", &"11".repeat(32)).unwrap();
        assign_config_option(&mut config, "service", "public-key", ENCODED_PUBLIC_KEY).unwrap();
        assert_eq!(config.service_key, DECODED_PUBLIC_KEY);
    }
}
