# Records docs/demo.gif from this checkout. Re-record after output changes with:
#   uv sync && vhs docs/demo.tape
# Scans the public, harmless fixture repo github.com/ag3ntsc4rn/autorun-audit-demo.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 600
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set WindowBar Colorful

# Use this checkout's build (uv sync puts it in .venv), so the GIF shows the current output.
Hide
Type "export PATH=$PWD/.venv/bin:$PATH PS1='$ ' && clear"
Enter
Sleep 500ms
Show

Sleep 600ms
Type "autorun-audit repo https://github.com/ag3ntsc4rn/autorun-audit-demo"
Sleep 700ms
Enter
Sleep 8s
