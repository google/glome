{
  pkgs ? import <nixpkgs> { },
  lib ? pkgs.lib,
}:

let
  version = (builtins.fromTOML (builtins.readFile ./rust/Cargo.toml)).package.version;
in
lib.makeScope pkgs.newScope (
  self:
  let
    inherit (self) callPackage;
  in
  {
    glome = callPackage (
      {
        stdenv,
        lib,

        nix-gitignore,

        meson,
        pkg-config,
        ninja,

        openssl,
        glib,
        pam,

        static ? stdenv.targetPlatform.isStatic,
      }:
      stdenv.mkDerivation {
        pname = "glome";
        inherit version;
        __structuredAttrs = true;

        src = nix-gitignore.gitignoreSource [
          ''
            *.nix
          ''
        ] ./.;

        nativeBuildInputs = [
          meson
          pkg-config
          ninja
        ];

        buildInputs =
          [
            openssl
            glib
          ]
          ++ (lib.optionals (!static) [
            pam
          ]);

        mesonFlags = [
          "-Dtests=true"
          "-Dpam-glome=${if static then "false" else "true"}"
          "-Dglome-cli=true"

          "-Ddefault_library=${if static then "static" else "shared"}"
          "-Ddefault_both_libraries=${if static then "static" else "shared"}"
          "-Dprefer_static=${if static then "true" else "false"}"
        ];

        doCheck = true;
      }
    ) { };

    glome-login-deb = callPackage (
      {
        stdenv,
        lib,

        fakeroot,
        fpm,
        buildPackages,

        glome,
      }:
      stdenv.mkDerivation {
        pname = "glome-login-deb";
        version = glome.version;
        __structuredAttrs = true;

        env = {
          packageArch = stdenv.targetPlatform.linuxArch;
          packageName = glome.pname;
          packageExt = "deb";
          packageType = "deb";
        };

        src = glome;

        nativeBuildInputs = [
          fakeroot
          fpm
          buildPackages.buildPackages.binutils-unwrapped
        ];

        buildPhase = ''
          runHook preBuild

          export HOME="$NIX_BUILD_TOP/home";
          mkdir -p $HOME

          mkdir -p rootfs/usr rootfs/usr/bin
          cp -R bin/glome-login rootfs/usr/bin
          cp -R etc rootfs/etc

          fakeroot fpm \
            -a "$packageArch" \
            -s dir \
            -t "$packageType" \
            --name "$packageName" \
            --version "$version" \
            -C rootfs \
            .
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          mkdir $out
          mv *."$packageExt" "$out"
          runHook postInstall
        '';
      }
    ) { };
  }
)
