# xray - Filter Hex-Rays Decompiler Output

xray is a plugin for the Hexrays decompiler that both filters and
colorizes the textual representation of the decompiler's output based
on configurable regular expressions.

This helps highlighting interesting code patterns which can be
useful in malware analysis and vulnerability identification.

![xray animated gif](/rsrc/xray.gif?raw=true)

## Installation/Updating:
xray installs or updates itself as a plugin by loading it as a
script using the "File->Script file..." (Alt-F7) menu item within IDA.

Running the plugin for the first time creates a default
configuration file "xray.cfg" within the folder
"%APPDATA%/Hex-Rays/IDA Pro/plugins/", which can and should then be
customized by the user.

While still under development, updating from a previous installation
of the plugin may introduce changes to the configuration file which may
cause incompatibility. If this is the case, the current configuration
file should be ported to the new format or deleted.

xray requires IDA 7.2+ (with some effort it may be backported to 7.0).

## Usage:
The plugin offers two distinct filtering/highlighting features:
* "xray", a persistent, configurable regular expression parser that
  applies color filters to the output of the Hexrays decompiler.
  This filter can be turned on and off using a keyboard shortcut as
  described in the next section.

  Persistent filtering attempts to match regular expressions taken
  from the plugin's configuration file against each of the decompiler's
  text lines. Successful matches will cause the background
  color of a matching text line to be changed accordingly.
  Optionally, changing the "high_contrast" setting to "1" in the
  configuration file will cause a visual "xray" effect.  

  For more settings and details, please refer to the comments in the
  configuration file.

* a dynamic filter that filters/highlights Hexrays output. This filter
  works similar to how the built-in filters for IDA "choosers" work.
  Possible "filter types" are "Regex" and "ASCII". Additional "filter
  options" determine how the filters are applied to respective Hexrays
  output:
  * "Text" removes any lines from the decompiler's output that a
    specified search term could not be matched against.
  * "Color" does not remove non-matching lines but only their respective
    color tags instead. This will cause matching text to be highlighted
    visually.

## Popup Menus/Keyboard shortcuts:
* F3:       Toggle xray
* Ctrl-R:   Reload xray configuration file and apply changes
            (edit and reload the configuration file on-the-fly)
* Ctrl-F:   Find ascii string/regular expression and apply
            filters based on Filter type and options.
            "Text": removes any non-matching lines from the outpout
            "Color": removes colors from non-matching lines

![xray3 animated gif](/rsrc/xray3.gif?raw=true)

## Contact:

Twitter: https://twitter.com/pat0is