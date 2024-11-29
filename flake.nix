{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11-small";
    flake-utils.url = "github:numtide/flake-utils";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  nixConfig = {
    extra-substituters = [
      "https://libsodium-hs.cachix.org"
    ];
    extra-trusted-public-keys = [
      "libsodium-hs.cachix.org-1:u/v4XdWrbl+G/fDUoEwB1yvMdlxdKM4al2odCNsrqkg="
    ];
    allow-import-from-derivation = true;
  };

  outputs = inputs@{ nixpkgs, ... }:
    let
      # this is to allow running `nix flake check` by using `--impure`
      systems =
        if builtins.hasAttr "currentSystem" builtins
        then [ builtins.currentSystem ]
        else nixpkgs.lib.systems.flakeExposed;
    in
    inputs.flake-utils.lib.eachSystem systems (system:
      let
        inherit (inputs.gitignore.lib) gitignoreSource;

        pkgs = import nixpkgs {
          inherit system;
          config.allowBroken = true;
        };

        pre-commit-check = inputs.pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            # nix checks
            nixpkgs-fmt.enable = true;
            deadnix.enable = true;
            statix.enable = true;

            # Haskell checks
            fourmolu.enable = true;
            cabal-fmt.enable = true;
            hlint.enable = true;
          };
        };

        hsPkgs = pkgs.haskellPackages.override (_old: {
          overrides = with pkgs.haskell.lib.compose; hself: hsuper:
            let
              commonOverrides = overrideCabal (_drv: {
                doInstallIntermediates = true;
                enableSeparateIntermediatesOutput = true;
                pkg-configDepends = [
                  pkgs.libsodium
                ];
              });
            in
            {
              libsodium-bindings = commonOverrides (hself.callCabal2nix "libsodium-bindings" (gitignoreSource ./libsodium-bindings) { });
              sel = commonOverrides (hself.callCabal2nix "sel" (gitignoreSource ./sel) {
                base16 = hsuper.base16_1_0;
                hedgehog = hsuper.hedgehog_1_4;
              });
            };
        });

        hsShell = hsPkgs.shellFor {
          shellHook = ''
            ${pre-commit-check.shellHook}
            set -x
            export LD_LIBRARY_PATH="${pkgs.libsodium}/lib"
            set +x
          '';

          packages = ps: with ps; [
            libsodium-bindings
            sel
          ];

          buildInputs = with hsPkgs; [
            pkgs.pkg-config
            pkgs.libsodium.dev
            cabal-install
            haskell-language-server
            hlint
            cabal-fmt
            fourmolu
          ];
        };

      in
      {
        checks = {
          inherit (hsPkgs) libsodium-bindings sel;
          shell = hsShell;
          formatting = pre-commit-check;
        };

        packages = {
          inherit (hsPkgs) libsodium-bindings sel;
        };

        devShells.default = hsShell;
      }
    );
}
