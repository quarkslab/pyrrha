# Pyrrha

* [Introduction](#introduction)
* [Installation](#installation)
* [Usage](#usage)
* [Docker](#docker)
* [Usage Example](#quick-start----usage-example)
* [Authors](#authors)

## Introduction

Pyrrha is a filesystem cartography and correlation software focusing on visualization. It currently focuses on relationship between executable files, but  aims at enabling anyone mapping and visualizing any kind of relationships. It uses the open-source code source
explorer [Sourcetrail](https://github.com/CoatiSoftware/Sourcetrail) to provide user a easy way to navigate through and search for 
path to function.

![](docs/img/imports.png)
<p align="center">
<b>An example of the symbols and libraries imported by <code>libgcc_s.so.1</code> and of the symbols which reference this library.</b>
</p>

![](docs/img/symlinks.png)
<p align="center">
<b>An example of the symlinks which point on <code>busybox</code>.</b>
</p>


## Installation
The installation is done in two parts:
- installing `Pyrrha` (as a Python module);
- installing `Sourcetrail` to be able to visualize Pyrra results.

### Sourcetrail installation
Sourcetrail can be installed using [its last realease](https://github.com/CoatiSoftware/Sourcetrail/releases/tag/2021.4.19) and its [documentation](https://github.com/CoatiSoftware/Sourcetrail/releases/tag/2021.4.19).

### Pyrrha installation
Pyrrha's installation compiles [SourcetrailDB](https://github.com/CoatiSoftware/SourcetrailDB) (Sourcetrail SDK) which require to have:
- `Cmake` >= 2.6;
- C++-Compiler with C++11 support.

Pyrrha requires a Python version >= 3.10.
It is recommended to install the Python package inside a virtualenv. You just can use `pip` to install it.
```commandline
$ git clone PYRRHA_URL
$ cd pyrrha
$ pip install '.'
```

*Tested for Linux and Windows.*

## Usage
First, create your db with `pyrrha`.

```commandline
Usage: pyrrha fs [OPTIONS] ROOT_DIRECTORY

  Map a filesystem into a sourcetrail compatible db.

Options:
  --db PATH  Sourcetrail DB file path (.srctrldb).  [default: pyrrha.srctrldb]
  --help     Show this message and exit.
```

Then, open the resulting project with `sourcetrail`. You can now navigate on the resulting cartography. The user interface is described in depth in the [Sourcetrail documentation](https://github.com/CoatiSoftware/Sourcetrail/blob/master/DOCUMENTATION.md#user-interface).

To match Sourcetrail language, the binaries, the exported functions and symbols, and the symlinks are represented as follows in Sourcetrail.

Binaries |      Exported functions      |      Exported symbols      | Symlinks
:---:|:----------------------------:|:--------------------------:| :---:
![](docs/img/classes.png) |  ![](docs/img/function.png)  | ![](docs/img/variable.png) | ![](docs/img/typedefs.png)


## Docker
`pyrrha` can be used with a docker. It provides Pyrrha bit you still need to install Sourcetrail on your system as described in the [Sourcetrail Installation](#sourcetrail-installation) section.

### Build
```commandline
$ docker build -t pyrrha .
```

### Usage
```commandline
$ cd ROOT_DIRECTORY/..
$ docker run -vt $PWD:/tmp/pyrrha pyrrha fs ROOT_DIRECTORY
```

## Quick Start- - Usage Example
Let's take the example of an [OpenWRT] firmware which is a common Linux distribution for embedded targets like routers.

First, download the firmware and extract its root-fs into a directory. Here we download the last OpenWRT version for generic x86_64 systems.
```commandline
$ wget https://downloads.openwrt.org/releases/22.03.5/targets/x86/64/openwrt-22.03.5-x86-64-rootfs.tar.gz -O openwrt_rootfs.tar.gz
$ mkdir openwrt_root_fs && cd openwrt_root_fs
$ tar -xf ../openwrt_rootfs.tar.gz
$ cd .. && rm openwrt_rootfs.tar.gz
```

Then we can run Pyrrha on it. It will produce some loges indicating which symlinks or imports cannot been solved directly by the tool. 
*(Do not forget to activate your virtualenv if you have created one for Pyrrha installation.)*
```commandline
$ pyrrha fs --db openwrt_db open_root_fs
$ ls 
openwrt_root_fs openwrt_db.srctrldb  openwrt_db.srctrlprj
```

You can now navigate into the resulting cartography with Sourcetrail.
```commandline
$ sourcetrail openwrt_db.srctrlprj
```

## Authors
- Eloïse Brocas (@ebrocas), Quarkslab