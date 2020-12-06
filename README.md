# FuncScanner
Collects extended function properties from IDA Pro databases.

This is especially useful in reverse engineering code that comes with no or little
symbolic information, as is often the case with embedded firmware.

## HowTo
* Finds number of cross references, loops and basic blocks of each function
* Order and filter results in a chooser widget
* All nodes that are part of a loop can be colored in graph view
* Results are directly saved with the current IDA database and reloaded once the plugin is (re)started
* Context menu allows the current database to be rescanned

## Example scenarios
* Sort by number of xrefs: find functions that are called statistically often (and hence find memcpy and candidates)
* Sort by number of loops: find complexity, parsers, crypto-related functions
* Sort by basic blocks: find complexity/simplicity

![FuncScanner screenshot](/rsrc/funcscanner.png)
