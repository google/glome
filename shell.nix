# run `nix-shell` in the same directory as this file
with import <nixpkgs> {};
stdenv.mkDerivation {
    name = "glome";
    buildInputs = [
      # Build dependencies
      # Compiler conforming to C99 (e.g. gcc, clang)
      meson     # >=0.49.2
      ninja
      pkg-config

      openssl   # >=1.1.1
      glib      # >=2.0   (glome-login and tests)
      linux-pam #         (PAM module)

      # Test dependencies
      libpam-wrapper

      # Development tools
      clang-tools
    ];
}
