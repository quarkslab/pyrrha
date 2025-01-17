# `fs-cg`: Inter Image Call Graph mapper

## Introduction

The `fs-cg` push deeper to `fs` mapper concept by mapping the call graph of
all executables on a firmware. So it not only relates imports to exports but
track precisely where within the executables. It is thus possible to know
precisely which function is called by which across the firmware. As such,
anyone can follow control-flow between programs.

The main drawback is that computing a program call graph requires disassembly
and is thus more computationaly intensive. That task is currently done using
the [Quokka exporter](https://github.com/quarkslab/quokka).



## Usage

This mapper uses the output of the `fs` mapper to resolve symlinks automatically.
The dump should be provided on the command line. The `ROOT_DIRECTORY` should contain
the whole filesystem to be indexed.

```commandline
Usage: pyrrha fs-cg [OPTIONS] ROOT_DIRECTORY

  Map a the Inter-Image Call Graph of a whole filesystem into a numbatui-compatible db.It disassembles executables
  using a disassembler and extract the call graph.It then results all call references across binaries.


Options:
  -d, --debug                  Set log level to DEBUG
  --db PATH                    NumbatUI DB file path (.srctrldb).  [default: pyrrha.srctrldb]
  -j, --jobs INT               Number of parallel jobs created (threads).  [default: 1; 1<=x<=11]
  --ignore                     When resolving duplicate imports, ignore them
  --arbitrary                  When resolving duplicate imports, select the first one available
  --interactive                When resolving duplicate imports, user manually select which one to use
  --fs-mapper-dump FILE        Pyrrha fs mapper dump.  [required]
  --disassembler DISASSEMBLER  Disassembler to use for disassembly.  [default: Disassembler.AUTO]
  --exporter EXPORTERS         Binary exporter to use for binary analysis.  [default: Exporters.AUTO]
  -h, --help                   Show this message and exit.
```

!!! note 
    This mapper create the Quokka export of each binary nearby each executable file. If this file already exists, it loads it without regenerate it. Like that it also allowed to use `pyrrha` in systems without Quokka and/or IDA. 


After firmware analysis, you can the resulting project with `numbatui`. You can now navigate on the resulting cartography. The user interface is described in depth in the [NumbatUI documentation](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#user-interface).
Do not hesitate to take a look at  all the possibilities offered by NumbatUI, especially [Custom Trails](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#custom-trail-dialog).