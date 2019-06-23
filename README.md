# xray - Filter Hex-Rays Decompiler Output

xray is a plugin for the Hexrays decompiler that both filters and
colorizes the textual representation of the decompiler's output based
on configurable regular expressions.

This helps highlighting interesting code patterns which can be
useful in malware analysis and vulnerability identification.

![xray animated gif](/rsrc/xray.gif?raw=true)

## Installation:
xray installs itself as a plugin by loading it as a script
using the "File->Script file..." (Alt-F7) menu item within IDA.

Running the plugin for the first time creates a default
configuration file (%APPDATA%/Hex-Rays/IDA Pro/plugins/xray.cfg)
which can and should be customized by the user.

IDA 7.2+ required.

## Usage:
The plugin offers two distinct filtering/highlighting features:
- "xray", a configurable regular expression parser that
  applies color filters to the output of the Hexrays decompiler.

  The plugin attempts to match regular expressions taken
  from its configuration file with each of the decompiler's
  text lines. Successful matches will cause the background
  color of a matching text line to be changed accordingly.
  Optionally, changing the "high_contrast" setting to "1" in the
  configuration file will cause a visual "xray" effect.  

  Please refer to the configuration file's comments for details.

- a "live" search function that filters/highlights Hexrays
  output.

## Popup Menus/Keyboard shortcuts:
- F3:       Toggle xray
- Ctrl-R:   Reload xraya configuration file and apply changes
            (edit the configuration file on-the-fly and add
            new regular expressions or change the default background
            color)
- Ctrl-F:   Find ascii string/regular expression and apply
            filters according to "Filter type" options.
            "Text": removes any non-matching lines from the outpout
            "Color": removes colors from non-matching lines

![xray3 animated gif](/rsrc/xray3.gif?raw=true)

## Contact:

Twitter: https://twitter.com/pat0is