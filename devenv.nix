{ pkgs, ... }:

{
  # https://devenv.sh/basics/
  env.GREET = "devenv";

  # https://devenv.sh/packages/
  packages = [ pkgs.git
              pkgs.llvm_16 ];

  # https://devenv.sh/languages/
  # languages.nix.enable = true;
}
