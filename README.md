# xexverify

xexverify is a tool I created to help defragment compressed .xex files (unencrypted files are untested and may require some code changes, but the underlying method would still work). You probably won't ever need this. I don't know that we even will, since compressed .xex files are not really all that common.

This tool does not handle every possible way in which a .xex file can be fragmented, and there are known ways in which it could fail. For example, if 2 compression windows/blocks in a row are fragmented, this code will fail to find an end to the garbage with `-N`. Same deal if the next block begins exactly on the boundary, and right after a fragment, as we won't have a valid decryption key. Similarly, the `-b` scan may fail if the first "chunk" of a new block falls exactly on an 0x4000 boundary which happens to also be the start of a fragment.

It is possible to write some more code to handle some, or perhaps all, of those cases, but at the time of writing, there has not been a need. Updates to this tool will only be made if we encounter a file which is fragmented in a way that's not already handled.

xex1tool benefits from some underlying changes, and is capable of reading some data from fragmented .xex files that the original version would fail to open. the idaxex loader is not the focus of this repo. there's absolutely no reason to use the version built from this repository, I just didn't bother removing it.

## Tool Usage Example:

First Command:

`xexverify.exe -N <xex_file>`

if the file is too fragmented, key detection may fail. You can provide an index with `-k`.

(key index: 0 for retail, 1 for devkit, 2 for retail-XEX1, 3 for devkit-XEX1)

The ouput should contain something along the lines of:
```
Fragmentation analysis for block 109:
  Block 109 starts at: 0x659000
  Block 109 size: 0xF800
  Expected end: 0x668800
  Actual next block: 0x17FC7C800
  Garbage offset: somewhere between 0x659000 and 0x17FC7C800
  Garbage size: 0x17F614000 bytes (392581 clusters)
```

In a hex editor or some other tool (I recommend ImHex), go to 0x659000 and go downwards until you find the start of bad data.

For the case of the example file, you would check at 0x65C000, 0x660000, 0x664000, etc. In my case (the .xex I developed this tool with/for), I got lucky and the frag is very obvious, beginning with many thousand 0xFF bytes.

---

Second Command:

`xexverify -b -f <start_of_garbage> -E <end_of_garbage> <xex_file>`

(remember your `-k` argument if auto detection does not work)

`start_of_garbage` is the offset you found manually, so 0x664000 in the example, and `end_of_garbage` is the value the previous scan found, rounded down to the nearest 0x4000, so 0x17FC7C000 in this example.

Look for something like this in the output:
```
Cluster assembly:
  FIXED (start): Cluster 406 (offset 0x658000)
  FIXED (start): Cluster 407 (offset 0x65C000)
  FIXED (start): Cluster 408 (offset 0x660000)
  FOUND: Cluster 392990 (offset 0x17FC78000)
  FIXED (end): Cluster 392991 (offset 0x17FC7C000)
```
the "FOUND" line is the end of the garbage. You can now remove the data between 0x664000 and 0x17FC78000. (the tool will not do this for you)

---

Repeat the above steps until there are no fragments left, then you should see
```
*** ALL BLOCKS VALID ***
Compressed data appears intact.
```

---

# idaxex (original README)

idaxex is a native loader plugin for IDA Pro, adding support for loading in Xbox360 XEX & Xbox XBE executables.

Originally started as an [IDAPython loader](https://github.com/emoose/reversing/blob/master/xbox360.py), work was continued as a native DLL to solve the shortcomings of it.

This should have the same features as xorloser's great Xex Loader (for IDA 6 and older), along with additional support for some early non-XEX2 formats, such as XEX1 used on beta-kits.

XBE files are additionally supported, adding a few extra features over the loader included with IDA.

## Supported formats

Includes support for the following Xbox executables:
- XEX2 (>= kernel 1861)
- XEX1 (>= 1838)
- XEX% (>= 1746)
- XEX- (>= 1640)
- XEX? (>= 1529)
- XEX0 (>= 1332)
- XBE (>= XboxOG ~3729)

## Features

- Can handle compressed/uncompressed images, and encrypted/decrypted (with support for retail, devkit & pre-release encryption keys)
- Reads in imports & exports into the appropriate IDA import/export views.
- Automatically names imports that are well-known, such as imports from the kernel & XAM, just like xorloser's loader would.
- PE sections are created & marked with the appropriate permissions as given by the PE headers.
- AES-NI support to help improve load times of larger XEXs.
- Marks functions from .pdata exception directory & allows IDA's eh_parse plugin to read exception information.
- Passes codeview information over to IDA, allowing it to prompt for & load PDBs without warnings/errors.
- Patched bytes can be written back to input file via IDA `Apply patches to input` option (works for all XBEs, XEX must be both uncompressed & decrypted using `xextool -eu -cu input.xex` first)
- XBE: adds kernel imports to IDA imports view
- XBE: tries naming SDK library functions using [XbSymbolDatabase](https://github.com/Cxbx-Reloaded/XbSymbolDatabase) & data from XTLID section

## Install
Builds for IDA 9 are available in the releases section.

To install the loader just extract the contents of the folder for your IDA version into IDA's install folder (eg. C:\Program Files\IDA Professional 9.0\)

I recommend pairing this loader with the PPCAltivec plugin, an updated version for IDA 7 is available at hayleyxyz's repo here: https://github.com/hayleyxyz/PPC-Altivec-IDA

## Building

Make sure to clone repo recursively for excrypt submodule to get pulled in.

**Windows**

Clone the repo into your idasdk\ldr\ folder and then build idaxex.sln with VS2022.

**Linux**

- Setup [ida-cmake](https://github.com/allthingsida/ida-cmake) in your idasdk folder
- Make sure IDASDK env var points to your idasdk folder
- Clone idaxex repo
- Run `cmake . -DEA64=YES` inside idaxex folder
- Run `make`
- To build xex1tool run cmake/make inside the xex1tool folder

On newest IDA you may need to edit ida-cmake common.cmake and change `libida64.so` to `libida.so` for build to link properly.

## Credits
Based on work by the Xenia project, XEX2.bt by Anthony, xextool 0.1 by xor37h, Xex Loader & x360_imports.idc by xorloser, xkelib, and probably many others I forgot to name.

Thanks to everyone involved in the Xbox 360 modding/reverse-engineering community!

XTLID parsing supported thanks to the [XboxDev/xtlid project](https://github.com/XboxDev/xtlid).

# xex1tool
Also included is an attempt at recreating xorloser's XexTool, for working with older pre-XEX2 executables.  
(The name is only to differentiate it from the original XexTool - it'll still support XEX2 files fine)

So far it can print info about the various XEX headers via `-l`, and extract the basefile (PE/XUIZ) from inside the XEX.

For XEX files that are both decrypted & decompressed xex1tool can also convert a VA address to a file offset for you, making file patching a little easier.

Support for other XexTool features may slowly be added over time (of course any help is appreciated!)
