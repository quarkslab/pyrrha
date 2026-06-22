# `fs-cg`: Inter Image Call Graph mapper

## Introduction

The `fs-cg` push deeper to `fs` mapper concept by mapping the call graph of
all executables on a firmware. So it not only relates imports to exports but
track precisely where within the executables. It is thus possible to know
precisely which function is called by which across the firmware. As such,
anyone can follow control-flow between programs.

The main drawback is that computing a program call graph requires disassembly
and is thus more computationaly intensive. That task is currently done using
either IDA Pro or Ghidra.



## Usage

This mapper uses the output of the `fs` mapper to resolve symlinks automatically.
The dump should be provided on the command line. The `ROOT_DIRECTORY` should contain
the whole filesystem to be indexed. 

!!! tip
    If your backend is not on  `PATH`, indicate its directory using the matching environment variable.
    ```sh
    export IDADIR=/opt/idapro 
    export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC  
    ```

```bash            
 Usage: pyrrha fs-cg [OPTIONS] ROOT_DIRECTORY                                                                           
                                                                                                                        
 Map the inter-image call graph of a whole filesystem into a NumbatUI db. It disassembles executables, extracts the     
 call graph, and resolves all call references across binaries.                                                          
                                                                                                                        
╭─ Mapper Options ─────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --backend  -b  [ida|ghidra]    Backend to use. [default: 1]                                                          │
│ --db           PATH            NumbatUI DB file path (.srctrldb). [default: fs-cg.srctrldb]                          │
│ --jobs     -j  INT [1<=x<=11]  Number of parallel jobs. [default: 1]                                                 │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Resolution ─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ When resolving duplicate imports:                                                                                    │
│ --arbitrary    Select the first one available.                                                                       │
│ --interactive  User manually selects which one to use.                                                               │
│ --ignore       Ignore them.                                                                                          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --debug  -d  Set log level to DEBUG.                                                                                 │
│ --help   -h  Show this message and exit.                                                                             │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```


After firmware analysis, you can visualize and navigate into the results with `numbatui`. The user interface is described in depth in the [NumbatUI documentation](https://quarkslab.github.io/NumbatUI/interface/).

Do not hesitate to take a look at  all the possibilities offered by NumbatUI, especially [Custom Trails](https://quarkslab.github.io/NumbatUI/interface/#custom-trail).