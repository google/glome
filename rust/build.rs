// Generates man pages from the clap CLI definition.
//
// build.rs is compiled and run independently of the crate it belongs to, so
// it cannot simply `use` the `Cli` type from src/cli/bin.rs: that would make
// the crate a build-dependency of itself. Instead, the argument definitions
// live in src/cli/args.rs and are pulled in verbatim with include!(), which
// both this file and src/cli/bin.rs do.
use clap::CommandFactory;
use std::env;

include!("src/cli/args.rs");

fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=src/cli/args.rs");

    // Only bother when the binary itself is being built.
    if env::var_os("CARGO_FEATURE_CLI").is_none() {
        return Ok(());
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR should be set by cargo"));
    clap_mangen::generate_to(Cli::command(), &out_dir)
}
