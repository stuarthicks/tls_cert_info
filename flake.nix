{
  description = "tls_cert_info - view TLS certificate information";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in {
      packages = forAll (pkgs: rec {
        tls_cert_info = pkgs.buildGoModule {
          pname = "tls_cert_info";
          version = self.shortRev or self.dirtyShortRev or "dev";
          src = ./.;
          vendorHash = null;
          ldflags = [ "-s" "-w" ];
          meta.mainProgram = "tls_cert_info";
        };
        default = tls_cert_info;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell { packages = [ pkgs.go pkgs.just pkgs.goreleaser ]; };
      });
    };
}
