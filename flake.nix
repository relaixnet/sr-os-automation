{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }: flake-utils.lib.eachDefaultSystem (system: let
    pkgs = nixpkgs.legacyPackages.${system};
    pysros = (pkgs.python3.pkgs.buildPythonPackage rec {
      pname = "pysros";
      version = "25.10.1";
      format = "setuptools";

      src = pkgs.fetchFromGitHub {
        owner = "nokia";
        repo = "pysros";
        tag = version;
        hash = "sha256-PnUXE1OLyaI3HLkhG6lHoVk2c2oXo6bUNoHOCuWSleA=";
      };

      build-system = [
        pkgs.python3.pkgs.setuptools
      ];

      dependencies = [
        pkgs.python3.pkgs.ncclient
        pkgs.python3.pkgs.lxml
      ];

      pythonImportsCheck = [ "pysros" ];
    });
    python-env = (pkgs.python3.withPackages (ps: with ps; [
      rich
      pyyaml
      pysros
    ]));
  in {
    packages = {
      inherit pysros python-env;
    };
    devShells.default = pkgs.mkShell {
      buildInputs = [
        python-env
      ];
    };
  });
}
