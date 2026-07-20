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

//! GLOME Login challenge/response flow.
//!
//! PAM-specific I/O (prompting the user, syslog) is intentionally not here;
//! this module only builds the challenge and validates a response against
//! it, so it can be exercised without a real PAM conversation.

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::borrow::Cow;
use std::fmt::Write as _;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};

use crate::PrivateKey;

use super::config::Config;
use super::is_zeroed;

const MIN_ENCODED_AUTHCODE_LEN: usize = 10;
const DMI_UUID_PATH: &str = "/sys/class/dmi/id/product_uuid";
const DMI_UUID_SIZE: usize = 36;

/// If `private_key` is all-zero, a new keypair is generated and written
/// back into `private_key`; otherwise the public key is derived from it.
fn derive_or_generate_key(private_key: &mut [u8; 32]) -> [u8; 32] {
    let secret = if is_zeroed(private_key) {
        let secret = StaticSecret::random();
        *private_key = secret.to_bytes();
        secret
    } else {
        StaticSecret::from(*private_key)
    };
    DalekPublicKey::from(&secret).to_bytes()
}

// Characters that don't need percent-encoding in a URL path segment, beyond
// ASCII alphanumerics.
const VALID_URL_PATH_CHARS: &[u8] = b"-._~!$&'()*+,;=";

/// Percent-encodes `src` for use as a URL path segment, escaping every byte
/// in `extra` in addition to the bytes that are always escaped. Operates
/// byte-wise (rather than codepoint-wise), so multi-byte UTF-8 sequences
/// are escaped one byte at a time.
fn urlescape_path(src: &str, extra: &[u8]) -> String {
    let mut out = String::with_capacity(src.len());
    for &b in src.as_bytes() {
        if !extra.contains(&b) && (b.is_ascii_alphanumeric() || VALID_URL_PATH_CHARS.contains(&b)) {
            out.push(b as char);
        } else {
            write!(out, "%{b:02X}").unwrap();
        }
    }
    out
}

/// Builds the GLOME Login message from a host-id (with optional type
/// prefix) and an action, escaping `:` in the host-id/type since `:` is
/// used as their separator, and escaping everything unsafe in the action.
fn glome_login_message(host_id_type: Option<&str>, host_id: &str, action: &str) -> String {
    let mut message = String::new();
    if let Some(host_id_type) = host_id_type.filter(|t| !t.is_empty()) {
        message.push_str(&urlescape_path(host_id_type, b":"));
        message.push(':');
    }
    message.push_str(&urlescape_path(host_id, b":"));
    message.push('/');
    message.push_str(&urlescape_path(action, b""));
    message
}

/// Builds the "run a login shell for `username`" action string.
fn shell_action(username: &str) -> String {
    format!("shell={username}")
}

/// Returns the local hostname.
fn gethostname_string() -> Result<String, String> {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .map_err(|e| format!("gethostname failed: {e}"))
}

/// Resolves `hostname` to a fully-qualified domain name via `getaddrinfo`.
fn resolve_fqdn(hostname: &str) -> Result<String, String> {
    let hints = dns_lookup::AddrInfoHints {
        socktype: dns_lookup::SockType::DGram.into(),
        flags: libc::AI_CANONNAME,
        ..Default::default()
    };
    let mut results = dns_lookup::getaddrinfo(Some(hostname), None, Some(hints))
        .map_err(|e| format!("getaddrinfo failed: {}", std::io::Error::from(e)))?;
    let info = results
        .next()
        .ok_or_else(|| "getaddrinfo returned no results".to_string())?
        .map_err(|e| format!("getaddrinfo failed: {e}"))?;
    info.canonname
        .ok_or_else(|| "getaddrinfo did not return a canonical name".to_string())
}

/// Returns the local hostname, resolved to a fully-qualified domain name
/// if it isn't one already.
fn get_hostname() -> Result<String, String> {
    let hostname = gethostname_string()?;
    if hostname.contains('.') {
        return Ok(hostname);
    }
    resolve_fqdn(&hostname)
}

/// Falls back to the DMI product UUID if the hostname can't be determined.
fn get_machine_id() -> Result<String, String> {
    if let Ok(hostname) = get_hostname() {
        return Ok(hostname);
    }
    let uuid = std::fs::read_to_string(DMI_UUID_PATH)
        .map_err(|e| format!("reading DMI product UUID: {e}"))?;
    uuid.get(..DMI_UUID_SIZE)
        .map(str::to_string)
        .ok_or_else(|| "DMI product UUID file too short".to_string())
}

/// Builds the GLOME Login message for the configured (or auto-detected)
/// host-id and the login shell action for `config.username`.
fn create_login_message(config: &Config) -> Result<String, String> {
    let host_id = match &config.host_id {
        Some(host_id) => Cow::Borrowed(host_id.as_str()),
        None => Cow::Owned(get_machine_id()?),
    };
    let username = config
        .username
        .as_deref()
        .ok_or_else(|| "username not set".to_string())?;
    let action = shell_action(username);
    Ok(glome_login_message(
        config.host_id_type.as_deref(),
        &host_id,
        &action,
    ))
}

/// Builds the `v2/<handshake>/<message>/` challenge string embedding the
/// key-version index and our ephemeral public key.
///
/// Only the key-version *index* form of the handshake is implemented (as
/// opposed to embedding the service key as a one-byte *prefix*), since
/// `Config`'s `service_key_id` is always in `0..=127` (see
/// `config::parse_key_version`, the only way to set it) — the prefix form
/// can never be reached from this module. An optional message-tag prefix
/// is also never emitted here.
fn request_challenge(service_key_id: u8, public_key: &[u8; 32], message: &str) -> String {
    let mut handshake = Vec::with_capacity(1 + public_key.len());
    // High bit set indicates "key-version index" rather than "key prefix".
    handshake.push(service_key_id | 0x80);
    handshake.extend_from_slice(public_key);
    let handshake_encoded = URL_SAFE.encode(&handshake);
    format!("v2/{handshake_encoded}/{message}/")
}

/// Computes the tag we expect the remote service to have produced for
/// `message`, given our ephemeral private key (and its already-computed
/// public key, to avoid re-deriving it) and the service's public key.
///
/// This is the "verify" side of the GLOME tag construction: the acting
/// side's own public key comes first in the HMAC key, then the peer's
/// (self before peer, rather than peer before self as in tag generation).
/// The crate's public [`crate::verify`] can't be reused here since it only
/// returns a bool comparison against a candidate rather than the raw
/// bytes, so the same construction is repeated here.
fn expected_tag(
    ours: &StaticSecret,
    ours_public: [u8; 32],
    theirs: &DalekPublicKey,
    ctr: u8,
    msg: &[u8],
) -> [u8; 32] {
    let key = [ours.dh(theirs), ours_public, theirs.to_bytes()].concat();

    Hmac::<Sha256>::new_from_slice(&key)
        .expect("HMAC can take key of any size")
        .chain_update([ctr])
        .chain_update(msg)
        .finalize()
        .into_bytes()
        .into()
}

/// A built GLOME Login challenge, ready to be displayed to the user, along
/// with the (full, untruncated) authcode we expect back.
pub(super) struct Challenge {
    pub(super) prompt: String,
    pub(super) authcode_encoded: String,
    /// The GLOME Login message (host-id-type/host-id/action) the challenge
    /// was built from, for diagnostic logging.
    pub(super) message: String,
}

/// Builds the challenge and the expected authcode, through constructing
/// `prompt` — this does not read user input.
pub(super) fn build_challenge(config: &mut Config) -> Result<Challenge, String> {
    if is_zeroed(&config.service_key) {
        return Err("no service key configured".to_string());
    }

    let public_key = derive_or_generate_key(&mut config.secret_key);
    let message = create_login_message(config)?;

    let secret = StaticSecret::from(config.secret_key);
    let service_key = DalekPublicKey::from(config.service_key);
    let authcode = expected_tag(&secret, public_key, &service_key, 0, message.as_bytes());
    let authcode_encoded = URL_SAFE.encode(authcode);

    let challenge = request_challenge(config.service_key_id, &public_key, &message);
    let prompt = format!("{}{challenge}", config.prompt);

    Ok(Challenge {
        prompt,
        authcode_encoded,
        message,
    })
}

/// The possible failure points of the authcode check.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum AuthcodeError {
    /// The configured `min-authcode-len` exceeds the full authcode length.
    MinLenTooLong { min_authcode_len: u32 },
    /// `input` is shorter than the required minimum length.
    TooShort { min_len: usize, got: usize },
    /// `input` is longer than the full authcode.
    TooLong { full_len: usize, got: usize },
    /// `input` doesn't match the expected authcode.
    Invalid,
}

/// Checks `input` against the expected authcode: length bounds first, then
/// a constant-time comparison. `delay` is called right before the
/// comparison, to slow down brute-force attempts; it's injectable so tests
/// don't have to wait on it.
///
/// `input` is raw bytes rather than `&str`: the real PAM authtok can be
/// arbitrary bytes, and this doesn't require it to be valid UTF-8 --
/// invalid UTF-8 simply can't match the (always-ASCII) expected authcode.
pub(super) fn verify_authcode(
    challenge: &Challenge,
    input: &[u8],
    min_authcode_len: u32,
    delay: impl FnOnce(),
) -> Result<(), AuthcodeError> {
    let full_len = challenge.authcode_encoded.len();

    let mut min_len = MIN_ENCODED_AUTHCODE_LEN;
    if min_authcode_len as usize > min_len {
        if min_authcode_len as usize > full_len {
            return Err(AuthcodeError::MinLenTooLong { min_authcode_len });
        }
        min_len = min_authcode_len as usize;
    }

    let bytes_read = input.len();
    if bytes_read < min_len {
        return Err(AuthcodeError::TooShort {
            min_len,
            got: bytes_read,
        });
    }
    if bytes_read > full_len {
        return Err(AuthcodeError::TooLong {
            full_len,
            got: bytes_read,
        });
    }

    delay();

    let expected = &challenge.authcode_encoded.as_bytes()[..bytes_read];
    if bool::from(input.ct_eq(expected)) {
        Ok(())
    } else {
        Err(AuthcodeError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn decode_hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn test_derive() {
        let mut private_key =
            decode_hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let expected_public_key =
            hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        let public_key = derive_or_generate_key(&mut private_key);

        assert_eq!(public_key, expected_public_key);
        // Deriving must not modify an already-set private key.
        assert_eq!(
            private_key,
            decode_hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        );
    }

    #[test]
    fn test_generate() {
        let mut private_key = [0u8; 32];

        let public_key = derive_or_generate_key(&mut private_key);

        assert_ne!(private_key, [0u8; 32]);
        assert_ne!(public_key, [0u8; 32]);
    }

    #[test]
    fn test_urlescape_path() {
        assert_eq!(
            urlescape_path("hello-world_1.2~3", b""),
            "hello-world_1.2~3"
        );
        assert_eq!(urlescape_path("a/b", b""), "a%2Fb");
        assert_eq!(urlescape_path("a:b", b":"), "a%3Ab");
        // ':' is already escaped by default (not in VALID_URL_PATH_CHARS),
        // so passing it as `extra` is a no-op today; the parameter is kept
        // for other potential escape sets.
        assert_eq!(urlescape_path("a:b", b""), "a%3Ab");
        assert_eq!(urlescape_path("é", b""), "%C3%A9");
    }

    #[test]
    fn test_glome_login_message_without_type() {
        // '=' is a "valid" (unescaped) URL path character, '/' is not.
        assert_eq!(
            glome_login_message(None, "myhost", "exec=/bin/sh"),
            "myhost/exec=%2Fbin%2Fsh"
        );
    }

    #[test]
    fn test_glome_login_message_with_type() {
        assert_eq!(
            glome_login_message(Some("hostname"), "my:host", "shell=root"),
            "hostname:my%3Ahost/shell=root"
        );
    }

    #[test]
    fn test_glome_login_message_empty_type_is_omitted() {
        assert_eq!(
            glome_login_message(Some(""), "myhost", "shell=root"),
            glome_login_message(None, "myhost", "shell=root")
        );
    }

    // Vector 1 from docs/login-v2-test-vectors.yaml: alice builds the
    // challenge (her ephemeral key is embedded in the handshake), bob is
    // the service (his key is `service_key` and produces the expected
    // authcode).
    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const VECTOR_1_MESSAGE: &str = "mytype:myhost/root";
    // The vector's own "message" field is
    // "v2/gIUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05qlyPH/mytype:myhost/root/",
    // but that embeds a 3-byte message-tag prefix (see the vector's
    // "prefix-length: 3") that this module never generates (see
    // request_challenge's doc comment above). The expected value below is
    // the same handshake with that prefix stripped, i.e. just
    // 0x80 || alice's public key, base64url-encoded.
    const VECTOR_1_CHALLENGE: &str =
        "v2/gIUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q/mytype:myhost/root/";
    const VECTOR_1_TAG: &str = "BB4BYjXonlIRtXZORkQ5bF5xTZwW6o60ylqfCuyAHTQ=";

    #[test]
    fn test_shell_action() {
        assert_eq!(shell_action("root"), "shell=root");
    }

    #[test]
    fn test_request_challenge_matches_vector_1() {
        let public_key = decode_hex32(ALICE_PUBLIC);
        assert_eq!(
            request_challenge(0, &public_key, VECTOR_1_MESSAGE),
            VECTOR_1_CHALLENGE
        );
    }

    #[test]
    fn test_expected_tag_matches_vector_1() {
        let ours = StaticSecret::from(decode_hex32(ALICE_PRIVATE));
        let ours_public = decode_hex32(ALICE_PUBLIC);
        let theirs = DalekPublicKey::from(decode_hex32(BOB_PUBLIC));
        let tag = expected_tag(&ours, ours_public, &theirs, 0, VECTOR_1_MESSAGE.as_bytes());
        assert_eq!(URL_SAFE.encode(tag), VECTOR_1_TAG);
    }

    fn test_config() -> Config {
        Config {
            service_key: decode_hex32(BOB_PUBLIC),
            secret_key: decode_hex32(ALICE_PRIVATE),
            username: Some("root".to_string()),
            host_id: Some("myhost".to_string()),
            host_id_type: Some("mytype".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_build_challenge_no_service_key_is_an_error() {
        let mut config = test_config();
        config.service_key = [0; 32];
        assert!(build_challenge(&mut config).is_err());
    }

    #[test]
    fn test_build_challenge_no_username_is_an_error() {
        let mut config = test_config();
        config.username = None;
        assert!(build_challenge(&mut config).is_err());
    }

    #[test]
    fn test_build_challenge_keeps_configured_secret_key() {
        let mut config = test_config();
        build_challenge(&mut config).expect("should build");
        assert_eq!(config.secret_key, decode_hex32(ALICE_PRIVATE));
    }

    #[test]
    fn test_build_challenge_generates_secret_key_when_unset() {
        let mut config = test_config();
        config.secret_key = [0; 32];
        build_challenge(&mut config).expect("should build");
        assert_ne!(config.secret_key, [0; 32]);
    }

    #[test]
    fn test_verify_authcode_round_trip() {
        let mut config = test_config();
        let challenge = build_challenge(&mut config).expect("should build");

        // Full authcode is accepted.
        assert!(
            verify_authcode(&challenge, challenge.authcode_encoded.as_bytes(), 0, || {}).is_ok()
        );
        // A truncated (but long enough) prefix is accepted too.
        let truncated = &challenge.authcode_encoded.as_bytes()[..MIN_ENCODED_AUTHCODE_LEN];
        assert!(verify_authcode(&challenge, truncated, 0, || {}).is_ok());
    }

    #[test]
    fn test_verify_authcode_too_short() {
        let mut config = test_config();
        let challenge = build_challenge(&mut config).expect("should build");
        let too_short = &challenge.authcode_encoded.as_bytes()[..MIN_ENCODED_AUTHCODE_LEN - 1];
        assert_eq!(
            verify_authcode(&challenge, too_short, 0, || {}),
            Err(AuthcodeError::TooShort {
                min_len: MIN_ENCODED_AUTHCODE_LEN,
                got: MIN_ENCODED_AUTHCODE_LEN - 1
            })
        );
    }

    #[test]
    fn test_verify_authcode_too_long() {
        let mut config = test_config();
        let challenge = build_challenge(&mut config).expect("should build");
        let full_len = challenge.authcode_encoded.len();
        let too_long = format!("{}A", challenge.authcode_encoded);
        assert_eq!(
            verify_authcode(&challenge, too_long.as_bytes(), 0, || {}),
            Err(AuthcodeError::TooLong {
                full_len,
                got: full_len + 1
            })
        );
    }

    #[test]
    fn test_verify_authcode_invalid() {
        let mut config = test_config();
        let challenge = build_challenge(&mut config).expect("should build");
        let wrong = "A".repeat(challenge.authcode_encoded.len());
        assert_eq!(
            verify_authcode(&challenge, wrong.as_bytes(), 0, || {}),
            Err(AuthcodeError::Invalid)
        );
    }

    #[test]
    fn test_verify_authcode_min_len_too_long() {
        let mut config = test_config();
        let challenge = build_challenge(&mut config).expect("should build");
        let full_len = challenge.authcode_encoded.len();
        let min_len = (full_len + 1) as u32;
        assert_eq!(
            verify_authcode(
                &challenge,
                challenge.authcode_encoded.as_bytes(),
                min_len,
                || {}
            ),
            Err(AuthcodeError::MinLenTooLong {
                min_authcode_len: min_len
            })
        );
    }

    #[test]
    fn test_get_hostname_smoke() {
        // Environment-dependent (hostname/DNS), so only check that the
        // always-available `gethostname(2)` path works.
        gethostname_string().expect("gethostname should succeed");
    }
}
