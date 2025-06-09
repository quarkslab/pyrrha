--8<-- "README.md:intro"

<div class="grid cards" markdown>

- ![](img/imports.png) <center> _Symbols and libraries imported by `libgcc_s.so.1`._</center>

- ![](img/symlinks.png) <center>_Symlinks pointing on `busybox`._</center>
</div>

## Installation
The installation is done in three parts:

1. Install mapper external dependencies: IDA dissassembler (with the decompilation option for the `exe-decomp` mapper) and [`Quokka` IDA plugin](https://github.com/quarkslab/quokka/releases).
1. Install `Pyrrha` itself.
1. Install [`NumbatUI`](https://github.com/quarkslab/NumbatUI) (or [`Sourcetrail`](https://github.com/CoatiSoftware/Sourcetrail)) to be able to visualize Pyrrha's results. 

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

!!! note
    Detailed instructions can be found on the [dedicated documentation page](installation.md).

--8<-- "README.md:usage"
!!! note
    The detailed documentation of each mapper is available in the [documentation](mappers/mappers.md).

--8<-- "README.md:publications"
--8<-- "README.md:authors"