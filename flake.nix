{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      inherit (nixpkgs) lib;
      forSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      packages = forSystems (
        system:
        let
          pkgs = import self {
            pkgs = nixpkgs.legacyPackages."${system}";
            inherit lib;
          };
          staticCrossPkgs = import self {
            pkgs = (
              import nixpkgs {
                localSystem = {
                  inherit system;
                };
                crossSystem = {
                  isStatic = true;
                  config =
                    {
                      x86_64-linux = "x86_64-unknown-linux-musl";
                      aarch64-linux = "aarch64-unknown-linux-musl";
                    }
                    ."${system}";
                };
                config.replaceCrossStdenv =
                  { buildPackages, baseStdenv }:
                  buildPackages.withCFlags [
                    "-ffunction-sections"
                    "-fdata-sections"
                    "-Os"
                  ] baseStdenv;
              }
            );
            inherit lib;
          };
        in
        {
          inherit (staticCrossPkgs) glome-login-deb;
          inherit (pkgs) glome;
        }
      );
    };
}
