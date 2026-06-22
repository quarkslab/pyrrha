# `decomp`: Executable Decompilation mapper

## Introduction

This mapper is not a firmware mapper but an executable mapper. It will map its call graph and its decompiled code with cross-references within the source code. In order
the mapper will:

* Decompile all functions (with Hex-Rays or Ghidra) to dump the whole decompiled code
* Index all functions with the associated decompilation
* Apply cross-references between functions

## Usage

!!! tip
    If your backend is not on  `PATH`, indicate its directory using the matching environment variable.
    ```sh
    export IDADIR=/opt/idapro 
    export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC  
    ```

```commandline
Usage: pyrrha decomp [OPTIONS] EXECUTABLE

  Map a single executable call graph into a NumbatUI-compatible database. Also indexes the decompiled code along with
  all call cross-references.

Options:
  -d, --debug                 Set log level to DEBUG.
  --db PATH                   NumbatUI DB file path (.srctrldb).  [default: decomp.srctrldb]
  -b, --backend [ida|ghidra]  Backend to use.  [default: Backend.IDA]
  -e, --export                Create a JSON export of the resulting decompilation mapping.
  -h, --help                  Show this message and exit.
```
After firmware analysis, you can visualize and navigate into the results with `numbatui`. The user interface is described in depth in the [NumbatUI documentation](https://quarkslab.github.io/NumbatUI/interface/).

Do not hesitate to take a look at  all the possibilities offered by NumbatUI, especially [Custom Trails](https://quarkslab.github.io/NumbatUI/interface/#custom-trail).

## JSON export

With the `-e/--export` option, the mapper writes a JSON file next to the database (`<db>.json`) describing the result of the run. It is loaded back into an `ExportedDecompilation` object exposed by Pyrrha, so results can be post-processed without re-running a disassembler:

```python
from pyrrha_mapper.mappers import ExportedDecompilation

result = ExportedDecompilation.from_json_export("my_binary.json")
for func in result.iter_functions():
    print(hex(func.addr), func.name, func.type)
```

An `ExportedDecompilation` stores the analysed binary identity (`path`, `id`, `name`) and its functions, keyed by their parser-space entry-point address. Each function is an `ExportedFunction` carrying its `Symbol`, its `FuncType`, the addresses it calls and is called by, its decompiled `source`, and the in-source locations of its declaration and call sites (`ExportedLocation`).
