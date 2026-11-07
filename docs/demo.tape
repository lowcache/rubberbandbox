# Renders docs/demo.gif from the repo root:  nix shell nixpkgs#vhs -c vhs docs/demo.tape
Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1500
Set Height 960
Set Padding 24
Set TypingSpeed 45ms
Set Theme "Catppuccin Mocha"

# Load the dev shell off-camera so the recording starts clean.
Hide
Type `eval "$(nix print-dev-env 2>/dev/null)" && clear`
Enter
Sleep 20s
Show

Type "python -m rubberbandbox.cli demo --pace 0.25"
Sleep 600ms
Enter
Sleep 24s
