# VHS tape for docs/demo.gif.
#
#     vhs docs/demo.tape
#
# Run it from the repository root. Everything below is offline: the fixture
# replaces OSV.dev, so the demo never touches the network.
#
# If `vhs` is not installed, `python3 docs/render_demo.py` produces an
# equivalent GIF from the same commands (see the repository README).

Output docs/demo.gif

Set Shell bash
Set FontSize 15
Set FontFamily "DejaVu Sans Mono"
Set Width 1060
Set Height 1160
Set Padding 24
Set Margin 0
Set TypingSpeed 0.01s
Set CursorBlink false

Type "export AUDITOR_OSV_FIXTURE=examples/osv-fixture.json"
Enter
Sleep 400ms

# A run that fails: requests 2.19.0 has a critical vulnerability.
Type "./app examples"
Enter
Sleep 4s
Type "echo \"exit code: $?\""
Enter
Sleep 1s

# A run that passes: nothing reaches the `critical` threshold here.
Type "./app --fail-on critical examples/package.json"
Enter
Sleep 3s
Type "echo \"exit code: $?\""
Enter
Sleep 2s
