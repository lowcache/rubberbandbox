{
  description = "Rubber Sandbox reference implementation";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs =
    { nixpkgs, ... }:
    let
      forAll = f: nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (s: f nixpkgs.legacyPackages.${s});
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [ ps.pytest ps.hypothesis ps.anthropic ]))
            pkgs.bubblewrap # the box launcher for local MCP servers
            pkgs.mcp-server-filesystem # official MCP filesystem server, boxed in tests
          ];
        };
      });
    };
}
