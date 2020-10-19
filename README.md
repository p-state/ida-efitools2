# About
It is an IDA plugin for extending UEFI reverse engineering capabilities. Based on [ida-efitools](https://github.com/danse-macabre/ida-efitools) with a bunch of fixes and new features.
Works with both Python 2 and Python 3. Supports outdated versions of IDA Pro 7.x with no guarantees.

# Features
* GUIDs defining
* Structures propagating (registers, xrefs, stack vars)
* Protocols & interfaces identification
* Unknown protocols initialization

# Extended features
* It can be used as a plugin and as a script.
* Automatically imports custom C declarations (structs, enums, unions, typedefs) from `efitools2/types` directory
* Sets permissions of code segment to RWE (to fix incorrect dead code elimination in decompiler view)

### Plugin-only features
* Provides ability to sync external types
* Prints and copies to clipboard selected EFI_GUID from disassembler view
* Extracts EFI_GUID from local variable assignments

# Important notes
* behemoth.til is rejected in favor of IDA's uefi.til and uefi64.til
* Do not use uefi(64).til from IDA 7.3 because it has errors

# Usage
### As script
Just run `efitools2/efitools.py` from IDA.

### As plugin
Hotkeys:

* **Ctrl-Alt-E** - does all the magic
* **Ctrl-Alt-G** (on data) - print and copy EFI_GUID at current cursor location
* **Ctrl-Alt-G** (on code) - extract and copy EFI_GUID from local variable assignment (set cursor at `EFI_GUID.data1` assignment)
* **F5** (on Local Types window) - synchronize local types from `types` folder

# Adjustment
* Hotkeys can be configured in `ida-efitool2.py` file.
* A few preferences can be found in `efitools2/efitools.py` file.
* Custom GUIDs should be placed within `efitools2/guids/custom.ini` file.
* Custom protocols should be placed inside `efitools2/types` folder. See available examples.

# How to export custom types
It's IDA's built-in feature. Just open the context menu for the type in Local Types window and select 'Export to header file' action.

# Prerequisites
* `pip install future` - For Python 2 only.
* `pip install clipboard` - If you want to automatically copy EFI_GUID contents to the clipboard.

# Plugin installation
Just copy `ida-efitools2.py` file and `efitools2` folder to IDA's plugins directory.

# Credits
[@snare](https://github.com/snare) for original code base of [ida-efiutils](https://github.com/snare/ida-efiutils).
[@danse-macabre](https://github.com/danse-macabre) for rewritten from scratch [ida-efitools](https://github.com/danse-macabre/ida-efitools).
[@djpohly](https://github.com/djpohly), [@al3xtjames](https://github.com/al3xtjames), [@vutung2311](https://github.com/vutung2311) for contributions (forks).
[@p-state](https://github.com/vutung2311) (me) for breathing a new life into
this.