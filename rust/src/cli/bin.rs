use base64::{alphabet, engine, engine::general_purpose, Engine as _};
use clap::{Args, Parser, Subcommand};
use glome::PrivateKey;
use std::convert::TryInto;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Glome,
}

#[derive(Args)]
struct TagArgs {
    /// Path to secret key
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,
    /// Path to peer's public key
    #[arg(short, long, value_name = "FILE")]
    peer: PathBuf,
    /// Message counter index
    #[arg(short, long, value_name = "n")]
    counter: Option<u8>,
}

#[derive(Args)]
struct VerifyArgs {
    /// Path to secret key
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,
    /// Path to peer's public key
    #[arg(short, long, value_name = "FILE")]
    peer: PathBuf,
    /// Message counter index
    #[arg(short, long, value_name = "n")]
    counter: Option<u8>,
    /// Minimum tag length
    ///
    /// Ideally a multiple of 4, defaults to 10 matching the
    /// MIN_ENCODED_AUTHCODE_LEN in login/login.h.
    /// Must be at least 2 and will be increased to 2 if the argument is lower.
    #[arg(long, value_name = "n", default_value_t = 10)]
    min_tag_length: u8,
    /// Tag to verify
    tag: String,
}

#[derive(Args)]
struct LoginArgs {
    /// Path to secret key
    #[arg(short, long, value_name = "FILE")]
    key: PathBuf,
    /// Challenge to generate a tag for
    challenge: String,
}

#[derive(Subcommand)]
enum Glome {
    /// Generate a new secret key and print it to stdout
    Genkey,
    /// Read a private key from stdin and write its public key to stdout
    Pubkey,
    /// Tag a message read from stdin
    Tag(TagArgs),
    /// Verify a message tag
    Verify(VerifyArgs),
    /// Generate a tag for a GLOME-Login challenge
    Login(LoginArgs),
}

type CommandResult = Result<(), Box<dyn Error>>;

fn genkey(stdout: &mut dyn io::Write) -> CommandResult {
    Ok(stdout.write_all(StaticSecret::random().as_bytes())?)
}

fn pubkey(stdin: &mut dyn io::Read, stdout: &mut dyn io::Write) -> CommandResult {
    let mut buf: [u8; 32] = [0; 32];
    stdin.read_exact(&mut buf)?;
    let sk: StaticSecret = buf.into();
    let pk: PublicKey = (&sk).into();

    Ok(writeln!(
        stdout,
        "glome-v1 {}",
        general_purpose::URL_SAFE.encode(pk.as_bytes())
    )?)
}

fn read_key(path: &PathBuf) -> Result<[u8; 32], Box<dyn Error>> {
    let b: Box<[u8; 32]> = fs::read(path)
        .map_err(|e| format!("reading file {:?}: {}", path, e))?
        .into_boxed_slice()
        .try_into()
        .map_err(|_| "private key must have exactly 32 bytes")?;
    Ok(*b)
}

fn read_pub(path: &PathBuf) -> Result<[u8; 32], Box<dyn Error>> {
    let pubkey = fs::read_to_string(path).map_err(|e| format!("reading file {:?}: {}", path, e))?;
    let b64 = match pubkey.strip_prefix("glome-v1 ") {
        Some(tail) => tail.trim_end(),
        None => return Err("unsupported public key version, expected 'glome-v1'".into()),
    };
    let raw: Box<[u8; 32]> = general_purpose::URL_SAFE
        .decode(b64)
        .map_err(|e| format!("decoding public key: {}", e))?
        .into_boxed_slice()
        .try_into()
        .map_err(|_| "public key must have exactly 32 bytes")?;
    Ok(*raw)
}

fn gentag(args: &TagArgs, stdin: &mut dyn io::Read, stdout: &mut dyn io::Write) -> CommandResult {
    let ours: StaticSecret = read_key(&args.key)?.into();
    let theirs: PublicKey = read_pub(&args.peer)?.into();
    let ctr = args.counter.unwrap_or_default();
    let mut msg = Vec::new();
    stdin.read_to_end(&mut msg)?;

    let t = glome::tag(&ours, &theirs, ctr, &msg);

    let encoded = general_purpose::URL_SAFE.encode(t);

    Ok(stdout.write_all(encoded.as_bytes())?)
}

fn verify(args: &VerifyArgs, stdin: &mut dyn io::Read) -> CommandResult {
    let min_tag_length = if args.min_tag_length > 2 {
        args.min_tag_length
    } else {
        2
    };
    let ours: StaticSecret = read_key(&args.key)?.into();
    let theirs: PublicKey = read_pub(&args.peer)?.into();
    let ctr = args.counter.unwrap_or_default();
    let mut msg = Vec::new();
    stdin.read_to_end(&mut msg)?;

    // We want to allow truncated tags, but not all truncations are valid
    // base64. A single encoded byte only holds 6 bits and can't be decoded
    // into a byte, so we need to ignore it by stripping it off.
    let mut tag_b64 = args.tag.clone();
    if tag_b64.len() % 4 == 1 {
        tag_b64.truncate(tag_b64.len() - 1);
    }

    // Ensure that we're comparing at least one byte.
    if tag_b64.len() < min_tag_length.into() {
        return Err("tag too short".into());
    }

    // Truncation can cause trailing bits and missing padding if the truncated
    // length is not a multiple of 4. Make sure that the base64 engine can deal
    // with that.
    let permissive_config = engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(engine::DecodePaddingMode::Indifferent);
    let permissive_engine = engine::GeneralPurpose::new(&alphabet::URL_SAFE, permissive_config);

    if !glome::verify(
        &ours,
        &theirs,
        ctr,
        &msg,
        &permissive_engine.decode(tag_b64)?,
    ) {
        return Err("tags did not match".into());
    }
    Ok(())
}

fn login(args: &LoginArgs, stdout: &mut dyn io::Write) -> CommandResult {
    let ours: StaticSecret = read_key(&args.key)?.into();

    let challenge_start = match args.challenge.find("v2/") {
        Some(n) => n,
        None => return Err("challenge should have a v2/ prefix".into()),
    };
    let (_, challenge) = args.challenge.split_at(challenge_start + 3);
    let parts: Vec<_> = challenge.split("/").collect();
    if parts.len() != 4 || !parts[3].is_empty() {
        return Err("unexpected format".into());
    }
    let mut handshake = general_purpose::URL_SAFE.decode(parts[0])?;
    if handshake.len() < 33 {
        return Err("handshake too short".into());
    }
    let message_tag_prefix = handshake.split_off(33);
    let raw_public_key: [u8; 32] = handshake
        .split_off(1)
        .try_into()
        .expect("there should be exactly 33 bytes in the argument");
    let theirs: PublicKey = raw_public_key.into();

    // Check public key prefix, if present.
    let prefix = handshake[0];
    if prefix & 1 << 7 == 0 {
        let pubkey = ours.public_key().to_bytes();
        if pubkey[31] != prefix {
            return Err(format!("challenge was generated for a different key: our key has MSB {}, challenge requests {}", pubkey[31], prefix).into());
        }
    }

    let msg = [parts[1], parts[2]].join("/");

    // Check message tag in challenge, if present.
    let message_tag_prefix_len = message_tag_prefix.len();
    if message_tag_prefix_len > 0
        && !glome::verify(&ours, &theirs, 0, msg.as_bytes(), &message_tag_prefix)
    {
        return Err("unexpected message tag prefix".into());
    }

    let t = glome::tag(&ours, &theirs, 0, msg.as_bytes());

    let encoded = general_purpose::URL_SAFE.encode(t);

    Ok(stdout.write_all(encoded.as_bytes())?)
}

fn main() -> CommandResult {
    match &Cli::parse().command {
        Glome::Genkey => genkey(&mut io::stdout()),
        Glome::Pubkey => pubkey(&mut io::stdin(), &mut io::stdout()),
        Glome::Tag(tag_args) => gentag(tag_args, &mut io::stdin(), &mut io::stdout()),
        Glome::Verify(verify_args) => verify(verify_args, &mut io::stdin()),
        Glome::Login(login_args) => login(login_args, &mut io::stdout()),
    }
}

#[cfg(test)]
mod tests {
    use io::Write;
    use std::{fmt::Debug, path::Path};
    use tempfile::NamedTempFile;
    use yaml_rust2::{Yaml, YamlLoader};

    use super::*;

    #[derive(Debug)]
    struct Person {
        private: [u8; 32],
        public_cli: String,
    }

    impl From<&Yaml> for Person {
        fn from(case: &Yaml) -> Self {
            let private: [u8; 32] = hex::decode(case["private-key"]["hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let public_cli = case["public-key"]["glome-cli"]
                .as_str()
                .unwrap()
                .to_string();
            Person {
                private,
                public_cli,
            }
        }
    }

    #[derive(Debug)]
    struct TestVector {
        name: String,
        alice: Person,
        bob: Person,
        message: String,
        tag: String,
        host_id_type: String,
        host_id: String,
        action: String,
    }

    impl From<&Yaml> for TestVector {
        fn from(case: &Yaml) -> Self {
            TestVector {
                name: format!("vector-{:02}", case["vector"].as_i64().unwrap()),
                alice: (&case["alice"]).into(),
                bob: (&case["bob"]).into(),
                message: case["message"].as_str().unwrap().to_string(),
                tag: case["tag"].as_str().unwrap().to_string(),
                host_id_type: case["host-id-type"].as_str().unwrap().to_string(),
                host_id: case["host-id"].as_str().unwrap().to_string(),
                action: case["action"].as_str().unwrap().to_string(),
            }
        }
    }

    fn test_vectors() -> Vec<TestVector> {
        let rust_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set");
        let vectors_file = Path::new(&rust_dir).join("../docs/login-v2-test-vectors.yaml");
        let content = fs::read_to_string(vectors_file).expect("test vectors should be readable");
        let cases = &YamlLoader::load_from_str(&content).expect("test vectors should be yaml")[0];

        let mut vectors: Vec<TestVector> = Vec::new();
        for case in cases.as_vec().expect("top level should be a list") {
            vectors.push(case.into());
        }
        vectors
    }

    #[test]
    fn test_genkey() {
        let mut stdout = io::Cursor::new(Vec::new());
        genkey(&mut stdout).expect("genkey should work");
        assert_eq!(32, stdout.get_ref().len())
    }

    fn cursor_to_string(cursor: &io::Cursor<Vec<u8>>) -> String {
        std::str::from_utf8(cursor.get_ref().as_slice())
            .expect("all test vectors should be UTF-8")
            .to_string()
    }

    #[test]
    fn test_pubkey() {
        for tc in test_vectors() {
            for person in [tc.alice, tc.bob] {
                let mut stdin = io::Cursor::new(person.private);
                let mut stdout = io::Cursor::new(Vec::new());
                pubkey(&mut stdin, &mut stdout).expect("pubkey should work");
                let expected = format!("{}\n", person.public_cli);
                let actual = cursor_to_string(&stdout);
                assert_eq!(expected, actual, "vector {}", tc.name)
            }
        }
    }

    fn temp_file(content: &[u8]) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().expect("temp file should be creatable");
        temp_file
            .write_all(content)
            .expect("temp file should be writable");
        temp_file
    }

    fn login_message(tc: &TestVector) -> Vec<u8> {
        let host = if tc.host_id_type.is_empty() {
            &tc.host_id
        } else {
            &format!("{}:{}", tc.host_id_type, tc.host_id)
        };
        // Some test messages contain slashes, but we don't want to add a dependency for URL
        // escaping, so we just replace the one character that occurs in the test vectors.
        format!("{}/{}", host, tc.action.replace("/", "%2F")).into_bytes()
    }

    #[test]
    fn test_tag() {
        for tc in test_vectors() {
            let mut stdin = io::Cursor::new(login_message(&tc));
            let mut stdout = io::Cursor::new(Vec::new());
            let key_file = temp_file(&tc.bob.private);
            let peer_file = temp_file(tc.alice.public_cli.as_bytes());
            let args = TagArgs {
                key: key_file.path().to_path_buf(),
                peer: peer_file.path().to_path_buf(),
                counter: None,
            };
            gentag(&args, &mut stdin, &mut stdout).expect("gentag should work");

            let actual = cursor_to_string(&stdout);
            assert_eq!(tc.tag, actual, "vector {}", tc.name)
        }
    }

    #[test]
    fn test_verify() {
        for tc in test_vectors() {
            let key_file = temp_file(&tc.alice.private);
            let peer_file = temp_file(tc.bob.public_cli.as_bytes());

            for n in 2..=tc.tag.len() {
                let mut stdin = io::Cursor::new(login_message(&tc));
                let mut tag = tc.tag.clone();
                tag.truncate(n);
                let args = VerifyArgs {
                    key: key_file.path().to_path_buf(),
                    peer: peer_file.path().to_path_buf(),
                    counter: None,
                    min_tag_length: 2,
                    tag,
                };
                verify(&args, &mut stdin)
                    .map_err(|e| format!("test case {}: tag length {}: {}", tc.name, n, e))
                    .expect("should not fail")
            }

            {
                let mut stdin = io::Cursor::new(login_message(&tc));
                let args = VerifyArgs {
                    key: key_file.path().to_path_buf(),
                    peer: peer_file.path().to_path_buf(),
                    counter: None,
                    min_tag_length: 2,
                    tag: "MDEyMzQ1Njc4".to_owned(),
                };
                assert!(
                    verify(&args, &mut stdin).is_err(),
                    "test case {}: verify should fail for bad tag",
                    tc.name
                );
            }

            for n in 0..16 {
                let mut stdin = io::Cursor::new(login_message(&tc));
                let mut tag = tc.tag.clone();
                tag.truncate(n);
                let args = VerifyArgs {
                    key: key_file.path().to_path_buf(),
                    peer: peer_file.path().to_path_buf(),
                    counter: None,
                    min_tag_length: 16,
                    tag,
                };
                assert!(
                    verify(&args, &mut stdin).is_err(),
                    "test case {}: verify should fail for tag length {}",
                    tc.name,
                    n
                );
            }
        }
    }

    #[test]
    fn test_login() {
        for tc in test_vectors() {
            let mut stdout = io::Cursor::new(Vec::new());
            let key_file = temp_file(&tc.bob.private);
            let args = LoginArgs {
                key: key_file.path().to_path_buf(),
                challenge: tc.message,
            };
            login(&args, &mut stdout).expect("login should work");

            let actual = cursor_to_string(&stdout);
            assert_eq!(tc.tag, actual, "vector {}", tc.name)
        }
    }
}
