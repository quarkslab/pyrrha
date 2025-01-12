# `exe-decomp`: Executable Decompilation mapper

## Introduction

This mapper is not a firmware mapper but an executable mapper. It will map its call graph and its decompiled code with cross-references within the source code. In order
the mapper will:

* Export the executable (Quokka) to extract its call graph
* Decompile all functions (with Hex-Rays) to dump the whole decompiled code
* Index all functions with the associated decompilation
* Apply cross-references between functions

## Usage

```commandline
Usage: pyrrha exe-decomp [OPTIONS] EXECUTABLE

  Map a single executable call graph into a sourcetrail-compatible database.It also index the decompiled code
  along with all call cross-references.

Options:
  -d, --debug                  Set log level to DEBUG
  --db PATH                    Sourcetrail DB file path (.srctrldb).  [default: pyrrha.srctrldb]
  --disassembler DISASSEMBLER  Disassembler to use for disassembly.  [default: Disassembler.AUTO]
  -h, --help                   Show this message and exit.
```

## JumpTo Disassembler Feature

The mapper uses a NumbatUI feature to enable jumping from NumbatUI directly
to the given function in a disassembler. This feature is useful if one need
to perform more in-depth reverse-engineering of the given function. Such
feature requires an IDA Pro plugin to be installed. It can be done by copying
the ``numbatui_plugin.py`` in the IDA Pro plugin directory.
