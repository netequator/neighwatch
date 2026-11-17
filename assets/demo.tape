# VHS Tape for neighwatch terminal demo
# Requirements: vhs (https://github.com/charmbracelet/vhs)
# Usage: vhs assets/demo.tape

Output assets/demo.gif

Set Shell "bash"
Set FontSize 13
Set FontFamily "JetBrains Mono"
Set Width 920
Set Height 400
Set Theme "Monokai Pro"
Set Padding 18

Type "neighwatch -i eth0 --state-file state.json --ttl 86400"
Sleep 600ms
Enter

Sleep 1200ms
Sleep 1500ms
Sleep 2000ms
Sleep 3000ms
