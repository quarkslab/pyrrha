# Pyrrha: A mapper collection for firmware analysis
 <!-- # --8<-- [start:intro]-->

<p align="center">
  <a href="https://github.com/quarkslab/pyrrha/pypi">
    <img src="https://img.shields.io/pypi/v/pyrrha-mapper.svg">
  </a>
  <a href="https://github.com/quarkslab/pyrrha/releases">
    <img src="https://img.shields.io/github/actions/workflow/status/quarkslab/pyrrha/release.yml">
  </a>
  <a href="https://pypi.org/project/pyrrha-mapper/">
    <img src="https://img.shields.io/pypi/pyversions/pyrrha-mapper">
  </a>
  <img src="https://img.shields.io/pypi/dm/pyrrha-mapper"/>
  <img src="https://img.shields.io/github/license/quarkslab/pyrrha"/>
</p>


Pyrrha is a filesystem cartography and correlation software focusing on visualization. It currently focuses on the relationship between executable files but aims at enabling anyone to map and visualize any relationship types. It uses the open-source code source
explorer [NumbatUI](https://github.com/quarkslab/NumbatUI) to provide users with an easy way to navigate through and search for 
path to function.
 <!-- # --8<-- [end:intro]-->

![](docs/img/imports.png)
<p align="center">
<b>An example of the symbols and libraries imported by <code>libgcc_s.so.1</code> and of the symbols which reference this library.</b>
</p>

![](docs/img/symlinks.png)
<p align="center">
<b>An example of the symlinks which point on <code>busybox</code>.</b>
</p>

## Installation

The installation is done in three parts:

1. Install mapper external dependencies: IDA dissassembler (with the decompilation option for the `exe-decomp` mapper) and [`Quokka` IDA plugin](https://github.com/quarkslab/quokka/releases).
1. Install `Pyrrha` itself.
1. Install [`NumbatUI`](https://github.com/quarkslab/NumbatUI) (or [`Sourcetrail`](https://github.com/CoatiSoftware/Sourcetrail)) to be able to visualize Pyrrha's results. 

> [!NOTE]
> A quick start installation is available on [Pyrrha documentation](https://quarkslab.github.io/pyrrha/#installation).

 <!-- # --8<-- [start:usage]-->
## Usage

The usage workflow is composed of two steps which allow you to separate DB creation and result visualization.

1. Run Pyrrha to obtain NumbatUI compatible files (`*.srctrlprj` for the project file and `*.srctrldb` for the DB file). With the python package, you can just launch the command `pyrrha`.
2. Visualize your results with Sourcetrail/NumbatUI. 

 <!-- # --8<-- [end:usage] -->
> [!NOTE]
> The detailed documentation of each mapper is available in the [documentation](https://quarkslab.github.io/pyrrha/mappers/mappers/).

 <!-- # --8<-- [start:publications]-->
## Publications

Pyrrha presentations, including live demos:

- **Pyrrha & Friends: Diving into Firmware Cartography**, Eloïse Brocas & Robin Davis, *SSTIC*, Rennes, France, 2025. [[slides]](https://www.sstic.org/media/SSTIC2025/SSTIC-actes/pyrrha_diving_into_firmware_cartography/SSTIC2025-Slides-pyrrha_diving_into_firmware_cartography-brocas_david.pdf) [[video]](https://static.sstic.org/videos2025/1080p/pyrrha_diving_into_firmware_cartography.mp4) 

- **Pyrrha: navigate easily into your system binaries**, Eloïse Brocas, *Hack.lu*, Luxembourg, 2023. [[slides]](https://github.com/quarkslab/conf-presentations/blob/master/Confs/HackLu23/pyrrha.pdf) [[video]](https://www.youtube.com/watch?v=-dMl-SvQl4k) 

- **Map your Firmware!**, Eloïse Brocas, *Pass The SALT*, Lille, France, 2023. [[slides]](https://github.com/quarkslab/conf-presentations/blob/master/Confs/PTS23/PTS2023-Talk-14-Pyrrha-map-your-firmware.pdf) [[video]](https://passthesalt.ubicast.tv/videos/2023-map-your-firmware/) 

Theory behind implementations

- **Streamlining Firmware Analysis with Inter-Image Call Graphs and Decompilation**, Robin David, *RE//verse.io*, USA, 2025. [[slides]](https://github.com/quarkslab/conf-presentations/blob/master/Confs/REverse-25/REverse_firmware_analysis_2025.pdf) [[video]](https://www.youtube.com/watch?v=LsDnrfZt_Xs)

 <!-- # --8<-- [end:publications] -->

 <!-- # --8<-- [start:authors] -->
## Authors
- Eloïse Brocas (@ebrocas), Quarkslab
- Robin David (@RobinDavid), Quarkslab


### Past Contributors
- Pascal Wu (@pwu42), during his internship at Quarkslab
<!-- # --8<-- [end:authors] -->