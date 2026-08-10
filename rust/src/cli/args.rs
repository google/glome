use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

const EXAMPLES: &str = "\
Generate two key pairs:

  $ glome genkey | tee A | glome pubkey >A.pub
  $ glome genkey | tee B | glome pubkey >B.pub

A tags a message for B:

  $ echo hi | glome tag -k A -p B.pub

B verifies the tag A sent:

  $ echo hi | glome verify -k B -p A.pub \"$tag\"

Tags may be truncated, as long as at least --min-tag-length characters remain:

  $ echo hi | glome verify -k B -p A.pub \"${tag:0:12}\"

Generate a tag for a GLOME-Login challenge:

  $ glome login -kB v2/gIUg8AmJ...q05qlyPH/h/a/
";

#[derive(Parser)]
#[command(author, version, about, long_about = None, after_help = EXAMPLES)]
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
