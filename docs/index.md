--8<-- "README.md:intro"

<div class="grid cards" markdown>

- ![](img/imports.png) <center> _Symbols and libraries imported by `libgcc_s.so.1`._</center>

- ![](img/symlinks.png) <center>_Symlinks pointing on `busybox`._</center>
</div>

## Installation
 

??? code "Install Visualisation Tool"

    === "Sourcetrail"

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
            ```
        === "Windows"

            Download last Sourcetrail [release](https://github.com/CoatiSoftware/Sourcetrail/releases), unzip it and run the `setup.exe`.

        === "MacOS"

            Download last Sourcetrail [release](https://github.com/CoatiSoftware/Sourcetrail/releases), and install it following [Sourcetrail documentation](https://github.com/CoatiSoftware/Sourcetrail/releases).


    === "NumbatUI (Ubuntu/Debian)"

        _Tested only for last Ubuntu/Debian._

        Run the following script that will clone and build `NumbatUI` and install `Pyrrha`. `NumbatUI` executable will  be in `numbatui/build/Release/app`.

        ```sh
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
        ```

!!! code "Install Pyrrha"
    === ":fontawesome-brands-python: Python Package"
        Require a local installation of **IDA Pro 9.1+** and/or **Ghidra 12.0+**  except for `fs` mapper.
        ```python
        # in a virtualenv
        pip install pyrrha-mapper
        ```
    === ":fontawesome-brands-docker: Docker Image"
        Download the docker image from Github Registry, this image is backed by Ghidra. 

        ```sh
        docker pull ghcr.io/quarkslab/pyrrha:latest
        ```


!!! note
    Detailed instructions can be found on the [dedicated documentation page](installation.md).

--8<-- "README.md:usage"

!!! code "Run Pyrrha"
    === ":fontawesome-brands-python: Python Package"
        If your backend is not on  `PATH`, indicate its directory using the matching environment variable.
        ```sh
        export IDADIR=/opt/idapro 
        export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC  
        ```
        Run **Pyrrha**, to obtain NumbatUI/Sourcetrail compatible files.
        ```
        pyrrha MAPPER [OPTIONS] ROOT_DIRECTORY
        ```

    === ":fontawesome-brands-docker: Docker Image"
        Download the docker image from Github Registry, this image is backed by Ghidra.

        ```sh
        cd ROOT_DIRECTORY/..
        docker run  --rm -t -v $PWD:/tmp/pyrrha ghcr.io/quarkslab/pyrrha:latest MAPPER [OPTIONS] ROOT_DIRECTORY
        ```

!!! code "Visualize results"
    You should have a `*.srctrlprj` file corresponding to the project file and a `*.srctrldb` file for the DB. 
    Run `NumbatUI` or `Sourcetrail` on the project file. You can now navigate into the results.

    The user interface is described in depth in the [NumbatUI documentation](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#user-interface).
    Do not hesitate to take a look at  all the possibilities offered by NumbatUI, especially [Custom Trails](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#custom-trail-dialog).
!!! note
    The detailed documentation of each mapper is available in the [documentation](mappers/mappers.md).

--8<-- "README.md:publications"
--8<-- "README.md:authors"