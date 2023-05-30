# Pyrrha

Pyrrha is a filesystem mapper which cartographies firmwares more exactly,their ELF binaries (and the associated symlinks) with their relations (exports/imports).
It uses the open-source code source explorer (for c/cpp, Python, and Java) Sourcetrail to provide user the possibility to navigate and search in the resulting firmware mapping.

## Installation
The installation is done in two parts:
- installing `Pyrrha` (as a Python module);
- installing `Sourcetrail` to be able to visualize Pyrra results.

### Sourcetrail installation
SOurcetrail can be installed using [its last realease](https://github.com/CoatiSoftware/Sourcetrail/releases/tag/2021.4.19) and its [documentation](https://github.com/CoatiSoftware/Sourcetrail/releases/tag/2021.4.19).

### Pyrrha installation
Pyrrha's installation compiles [SourcetrailDB](https://github.com/CoatiSoftware/SourcetrailDB) (Sourcetrail SDK) which require to have:
- `Cmake` >= 2.6;
- C++-Compiler with C++11 support;
- SWIG.

#### Linux
It is recommended to install the Python package inside a virtualenv.
```python
$ pip install '.'
```

#### Windows
Not tested.

#### macOS
Not tested.

## Usage
First, create your db with `pyrrha`.

```commandline
Usage: pyrrha [OPTIONS] ROOT_DIRECTORY

  Map a filesystem into a sourcetrail compatible db.

Options:
  --db PATH  Sourcetrail DB file path (.srctrldb).  [default: pyrrha.srctrldb]
  --help     Show this message and exit.
```

Then, open the resulting project with `sourcetrail`.