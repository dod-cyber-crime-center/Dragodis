# Dragodis

Dragodis is a python scripting framework that allows the use of any disassembler in
reverse engineering related work.  This project provides a generic disassembler API that can be
integrated into anything from simple scripts to large tools and applications.  Once integrated,
the script/tool can be run using any disassembler supported by Dragodis as if it were
built to run with the specified disassembler from the start.  Dragodis currently supports
Ghidra and IDA.  
Dragodis is meant to be used for headless analysis.  The plan for the project is to first
build a flat API that will provide all the disassembler functionality that should be needed
and then later build an object-oriented API on top of the flat API for cleaner usage.  This version
of the project is very limited in what it can currently do.  It lacks a lot of core functionality
so this release is primarily a simple proof of concept.


## Installation

To complete the installation, first install Dragodis and then follow one or more of the following sets
of instructions to setup your desired disassembler(s).

```bash
pip install Dragodis
```

### IDA

1. Download and install [IDA Pro 7.*](hex-rays.com) with Python 3 mode. (Tested on version 7.4 and 7.5)

1. Set the `IDA_DIR` environment variable to point to the directory where IDA is installed. 
(e.g. `C:\Program Files\IDA Pro 7.5`)

1. Dragodis uses [jfx_bridge_ida](github.com/justfoxing/jfx_bridge_ida) to communicate with IDA.
    This is installed automatically when you install Dragodis. However, if you are using a different python environment 
    than IDA, you can manually install the library in the IDA environment using the `--target` flag.
    
    ```bash
    pip install jfx_bridge_ida --target=%IDA_DIR%\python\3 
    ```
   
1. Install the IDA bridge server script files into the IDA Python folder.
    ```bash
    python -m jfx_bridge_ida.install_server %IDA_DIR%\python\3
    ```


### Ghidra


1. Download and install [Ghidra](ghidra-sre.org) to a desired location.

1. Set the `GHIDRA_DIR` environment variable to point to the directory where Ghidra is installed. (e.g. `C:\Tools\ghidra_9.1.2_PUBLIC`)

1. Dragodis uses [ghidra_bridge](github.com/justfoxing/ghidra_bridge) to communicate with Ghidra. 
    Install the Ghidra bridge server script files into the `ghidra_scripts` folder in the user home folder.
    
    ```bash
    python -m ghidra_bridge.install_server ~/ghidra_scripts
    ```


## Usage


To use, simply pass in the path to your input binary file into either the `IDA` or `Ghidra` class.
This will create an instance of the disassembler with the given input file analyzed.


```python
import dragodis

with dragodis.Ghidra(r"C:\strings.exe") as ghidra:  
    print(ghidra.get_dword(0x401000))
```


```python
import dragodis

with dragodis.IDA(r"C:\strings.exe") as ida:  
    print(ida.get_dword(0x401000))
```

A disassembler can also be run without using a context manager using the `start()` and `stop()` functions.

```python
import dragodis

ghidra = dragodis.Ghidra(r"C:\strings.exe")  
ghidra.start()  
ghidra.get_dword(ghidra)  
ghidra.get_dword(0x401000)  
ghidra.stop()  
```

There is currently a limitation of the bridge that forces the IDA GUI to pop up when using IDA as the 
underlying disassembler.  IDA must be manually closed after use in order to save the .idb file.
This will be fixed in a future release.

Testing of Dragodis has been done with IDA 7.4, 7.5, and Ghidra 9.1.2.
