# importsort

This is a tool that I use to group imports from Windows binaries. 
Sometimes, you have a gigantic folder full of executables, and you want to figure out what you should look at first. 
importsort will iterate over all of the files in a directory, and create a list containing the DLL name, the function imported, and the file that imported that function. 
You can use it to analyze possible behavior, such as network functionality or registry key manipulation etc. 

The initial version of this tool used radare2 or rizin for parsing PE files. The new version relies on the `pefile` library. Install with `python3 -m pip install pefile`.
This newer version is much faster, and less error prone than the previous version.

## Usage

Parse a whole directory
```
python3 importsort.py -d someDirectory/
```

Parse a whole directory and output json
```
python3 importsort.py -d someDirectory/ -j
```
