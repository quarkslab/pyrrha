# `fs`: ELF/PE imports/exports and the associated symlinks


## Usage
### Mapping with Pyrrha 
First, create your db with `pyrrha`. The `ROOT_DIRECTORY` should contain the whole filesystem you want to map, it should be already extracted or mounted. `ROOT_DIRECTORY` will be considered by Pyrrha as the filesystem root for all the symlink resolutions. 

```commandline
Usage: Usage: pyrrha fs [OPTIONS] ROOT_DIRECTORY

  Map a filesystem into a numbatui-compatible db. It maps ELF and PE files, their imports and their exports plus
  the symlinks that points on these executable files.

Options:
  -d, --debug     Set log level to DEBUG
  --db PATH       NumbatUI DB file path (.srctrldb).  [default: pyrrha.srctrldb]
  -e, --json      Create a JSON export of the resulting mapping.
  -j, --jobs INT  Number of parallel jobs created (threads).  [default: 1; 1<=x<=16]
  --ignore        When resolving duplicate imports, ignore them
  --arbitrary     When resolving duplicate imports, select the first one available
  --interactive   When resolving duplicate imports, user manually select which one to use
  -h, --help      Show this message and exit.
```

You can also export your Pyrrha results as a JSON file (option `-j`) to be able to postprocess them. For example, you can diff the results between two versions of the same system and list the binaries added/removed and which symbols has been added/removed (*cf* example script in `example`).

### Visualization with NumbatUI
Open the resulting project with `numbatui`. You can now navigate on the resulting cartography. The user interface is described in depth in the [NumbatUI documentation](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#user-interface).

<figure markdown>
  ![](../img/imports.png)
  <figcaption> An example of the symbols and libraries imported by <code>libgcc_s.so.1</code> and of the symbols which reference this library.</figcaption>
</figure>

<figure markdown>
  ![](../img/symlinks.png)
  <figcaption> An example of the symlinks which point on <code>busybox</code>.</figcaption>
</figure>

Do not hesitate to take a look at [NumbatUI documentation](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#graph-view-1) to explore all the possibilities offered by Sourcetrail. [Custom Trails](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#custom-trail-dialog) could be really useful in a lot of cases.

!!! example "Demo"
    An live demo of how we can use NumbatUI to visualize this mapper results is available [here](https://www.youtube.com/watch?v=-dMl-SvQl4k&t=12m33s).

##  Quick Start—Usage Example
Let's take the example of an OpenWRT firmware which is a common Linux distribution for embedded targets like routers.

First, download the firmware and extract its root-fs into a directory. Here we download the last OpenWRT version for generic x86_64 systems.
```commandline
$ wget https://downloads.openwrt.org/releases/22.03.5/targets/x86/64/openwrt-22.03.5-x86-64-rootfs.tar.gz -O openwrt_rootfs.tar.gz
$ mkdir openwrt_root_fs && cd openwrt_root_fs
$ tar -xf ../openwrt_rootfs.tar.gz
$ cd .. && rm openwrt_rootfs.tar.gz
```

Then we can run Pyrrha on it. It will produce some logs indicating which symlinks or imports cannot be solved directly by the tool. 
*(Do not forget to activate your virtualenv if you have created one for Pyrrha installation.)*
```commandline
> pyrrha fs --db openwrt_db openwrt_root_fs
> ls 
openwrt_root_fs openwrt_db.srctrldb  openwrt_db.srctrlprj
```

You can now navigate into the resulting cartography with NumbatUI.
```commandline
> numbatui openwrt_db.srctrlprj
```

<figure markdown>
  ![](../img/example_sourcetrail.png)
  <figcaption> Pyrrha result opened with NumbatUI.</figcaption>
</figure>


## Postprocessing `fs` result: the diffing example

When you have to compare two bunch of executable files, for example two versions of the same firmware, it could be quickly difficult to determine where to start and have results in a short time. 

Diffing could be a solution. However, as binary diffing can be quite time-consuming, a first approach could be to diff the symbols contained in the binary files to determine which ones were added/removed. For example, using this technics can help you to determines quickly the files that have changed their internal structures versus the files that only contained little update of their dependency. To do that, you can use the JSON export of `fs` parser results.

The following script prints on the standard output the list of files that has been added/removed and then the symbol changes file by file.

???+ abstract "`examples/diffing_pyrrha_export.py`"

    ``` py 
    --8<-- "examples/diffing_pyrrha_exports.py"
    ```