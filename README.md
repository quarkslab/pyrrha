# Pyrrha: A mapper collection for firmware analysis

Pyrrha is a filesystem cartography and correlation software focusing on visualization. It currently focuses on the relationship between executable files but aims at enabling anyone to map and visualize any relationship types. It uses the open-source code source
explorer [NumbatUI](https://github.com/quarkslab/NumbatUI) to provide users with an easy way to navigate through and search for 
path to function.

![](img/imports.png)
<p align="center">
<b>An example of the symbols and libraries imported by <code>libgcc_s.so.1</code> and of the symbols which reference this library.</b>
</p>

![](img/symlinks.png)
<p align="center">
<b>An example of the symlinks which point on <code>busybox</code>.</b>
</p>


## Installation

The installation is done in three parts:

- Installing mapper external dependencies: 
      * IDA dissassembler (with the decompilation option for the `exe-decomp` mapper).
      * [`Quokka` IDA plugin](https://github.com/quarkslab/quokka/releases).
- Installing `Pyrrha` as a Python module (`pip install pyrrha-mapper` or from the sources).
- Installing [`NumbatUI`](https://github.com/quarkslab/NumbatUI) (or [`Sourcetrail`](https://github.com/CoatiSoftware/Sourcetrail)) to be able to visualize Pyrrha's results. 


!!! example "Quick Start" 

    === "Sourcetrail"

         1. Install Quokka plugin by downloaded the appropriate version from its [release](https://github.com/quarkslab/quokka/releases) page. Then follow the instructions according to your OS.

         2. Install Sourcetrail and Pyrrha.

            === "Linux"
                ```bash
                SOURCETRAIL_URL='https://github.com/CoatiSoftware/Sourcetrail/releases/download/2021.4.19/Sourcetrail_2021_4_19_Linux_64bit.tar.gz'
                CHECKSUM=""f65a401daad8e16f29f7b2ff062a559999b6a8d44606db36cdf803de0cd7816d
                EXTRACTION_DIR="/tmp/Sourcetrail_2021_4_19_Linux_64bit"
                DOWNLOAD_PATH="$EXTRACTION_PATH.tar.gz"

                wget $SOURCETRAIL_URL -O $DOWNLOAD_PATH
                echo $CHECKSUM $DOWNLOAD_PATH | sha256sum -c 

                if [ $? == 0 ]; then
                   echo '==== Install Sourcetrail'
                   tar xf $DOWNLOAD_PATH -C $EXTRACTION_DIR
                   sudo $EXTRACTION_DIR/Sourcetrail/install.sh
                   rm -rf $DOWNLOAD_PATH $EXTRACTION_DIR
                fi

                # Install pyrrha
                if [ $? == 0 ]; then
                   echo '==== Install Pyrrha'
                   pip install pyrrha-mapper
                fi
                ```
            === "Windows"

                  1. Download last Sourcetrail [release](https://github.com/CoatiSoftware/Sourcetrail/releases), unzip it and run the `setup.exe`.
                  2. Install pyrrha: `pip install pyrrha-mapper`

            === "MacOS"

                  1. Download last Sourcetrail [release](https://github.com/CoatiSoftware/Sourcetrail/releases), and install it following [Sourcetrail documentation](https://github.com/CoatiSoftware/Sourcetrail/releases).
                  2. Install pyrrha: `pip install pyrrha-mapper`


    === "NumbatUI (Ubuntu/Debian)"

         _Tested only for last Ubuntu/Debian._

         First install Quokka plugin by downloaded the appropriate version from its [release](https://github.com/quarkslab/quokka/releases) page.

         Then run the following script that will clone and build `NumbatUI` and install `Pyrrha`. `NumbatUI` will in `numbatui/build/Release/app`.

         ```
         # Prerequisites for Numbat UI
         sudo apt-get update
         sudo apt-get install -y \
                      cmake \
                      git \
                      build-essential \
                      libboost-filesystem-dev libboost-program-options-dev libboost-system-dev libboost-date-time-dev \
                      qt6-svg-dev qt6-base-dev qt6-5compat-dev \
                      unzip wget \
                      libclang-17-dev clang-17

         # Clone and Build NumbatUI
         git clone https://github.com/quarkslab/NumbatUI.git numbatui 
         cd numbatui
         mkdir -p build/Release 
         cd build/Release
         cmake -DCMAKE_BUILD_TYPE="Release" -DBUILD_CXX_LANGUAGE_PACKAGE=ON -DBUILD_PYTHON_LANGUAGE_PACKAGE=ON ../.. && make NumbatUI -j $(nproc)

         # Install pyrrha
         pip install pyrrha-mapper
         ```



Detailed instructions can be found on the [dedicated documentation page](https://quarkslab.github.io/pyrrha/installation/).

## Usage
The usage workflow is composed of two steps which allow you to separate DB creation and result visualization.

1. Run Pyrrha to obtain NumbatUI compatible files (`*.srctrlprj` for the project file and `*.srctrldb` for the DB file). With the python package, you can just launch the command:
   ```
   > pyrrha
   Usage: pyrrha [OPTIONS] COMMAND [ARGS]...

   Mapper collection for firmware analysis.

   Options:
    -h, --help  Show this message and exit.

   Commands:
    exe-decomp  Map an executable call graph with its decompiled code.
    fs          Map PE and ELF files of a filesystem into a sourcetrail-compatible db.
    fs-cg       Map the Call Graph of every firmware executable a sourcetrail-compatible db.

   ```
2. Visualize your results with Sourcetrail
   ```
   > numbatui PROJECT_NAME.srctrlprj
   ```

The detailed documentation of each mapper is available in the [documentation](https://quarkslab.github.io/pyrrha/mappers/mappers/).

## Publications

Pyrrha has been presented by Eloïse Brocas at two conferences listed below. These talks include live demo of the `fs` parser which map links between libraries and executables files.

- Pyrrha: navigate easily into your system binaries, *Hack.lu'23*. [[slides]](https://github.com/quarkslab/conf-presentations/blob/master/Confs/HackLu23/pyrrha.pdf) [[video]](https://www.youtube.com/watch?v=-dMl-SvQl4k) 
- Map your Firmware!, *PTS'23*. [[slides]](https://github.com/quarkslab/conf-presentations/blob/master/Confs/PTS23/PTS2023-Talk-14-Pyrrha-map-your-firmware.pdf) [[video]](https://passthesalt.ubicast.tv/videos/2023-map-your-firmware/) 

The theoritical details below the `fs-cg` and `exe-decomp` mappers implementation have been presented by Robin David.

- Streamlining Firmware Analysis with Inter-Image Call Graphs and Decompilation, *RE/verse.io 2025*. [[slides]](https://github.com/quarkslab/conf-presentations/blob/master/Confs/REverse-25/REverse_firmware_analysis_2025.pdf) [[video]](https://www.youtube.com/watch?v=LsDnrfZt_Xs)

## Authors
- Eloïse Brocas (@ebrocas), Quarkslab
- Robin David (@RobinDavid), Quarkslab


### Past Contributors
- Pascal Wu (@pwu42), during his internship at Quarkslab