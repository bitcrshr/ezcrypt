{
  description = "ezcrypt: SSH CA tooling (CLI)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: rec {
        ezcrypt = pkgs.rustPlatform.buildRustPackage {
          pname = "ezcrypt";
          version = (builtins.fromTOML (builtins.readFile ./crates/ezcrypt-cli/Cargo.toml)).package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          # Default features only: `test-hooks` must never be built into a shipped binary.
          cargoBuildFlags = [ "-p" "ezcrypt-cli" ];
          # .cargo/config.toml relocates the target dir; the install hook expects ./target.
          CARGO_TARGET_DIR = "target";
          doCheck = false;
          meta = {
            description = "Command-line client for the ezcrypt iPhone SSH CA";
            license = pkgs.lib.licenses.mit;
            mainProgram = "ezcrypt";
          };
        };
        default = ezcrypt;
      });

      apps = forAll (pkgs: rec {
        ezcrypt = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/ezcrypt";
        };
        default = ezcrypt;
      });
    };
}
