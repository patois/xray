# xray - Filter Hex-Rays Decompiler Output

xray is a plugin for the Hexrays decompiler that uses
regular expressions in order to highlight points-of-interest
of decompiled functions.

![xray animated gif](/rsrc/xray.gif?raw=true)

## Installation:
xray installs itself as a plugin by loading it as a script
using the "File->Script file..." (Alt-F7) menu item within IDA.

Running the plugin for the first time creates a default
configuration file (%APPDATA%Hex-Rays/IDA Pro/plugins/xray.cfg)
which can and should be customized by the user.

IDA 7.2+ required.

## Usage:
The plugin attempts to match regular expressions taken
from its configuration file with each of the decompiler's
text lines. Successful matches will cause the background
color of a matching text line to be changed, whereas any
non-matching lines will have their colors removed entirely,
thereby causing an "xray" effect.

This will help isolate relevant spots when browsing through
large decompiled functions.

Regular expressions as well as the background color should
be customized according to personal requirements.

## Popup Menus/Keyboard shortcuts:
- F3:       Toggle xray
- Ctrl-R:   Reload configuration (edit the configuration
            file on-the-fly and add new regular expressions
            or change the default background color)