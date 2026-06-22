---
title: Home
---

--8<-- "README.md:intro"

<div class="grid cards" markdown>

- ![](img/imports.png) <center> _Symbols and libraries imported by `libgcc_s.so.1`._</center>

- ![](img/symlinks.png) <center>_Symlinks pointing on `busybox`._</center>
</div>

## Installation
 

!!! note "Install Visualisation Tool"

    === "NumbatUI (Ubuntu/Debian)"

        For Debian like distribution, download the [`.deb`](https://github.com/quarkslab/NumbatUI/releases) package and install it on your system (`sudo dpkg -i numbatui.deb`)

        For other systems, you can also compile it manually or use a Docker, check [NumbatUI documentation](https://quarkslab.github.io/NumbatUI/installation/) for further details.

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

    
!!! note "Install Pyrrha"
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


!!! info
    Detailed instructions can be found on the [dedicated documentation page](installation.md).

--8<-- "README.md:usage"

!!! note "Run Pyrrha"
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

!!! note "Visualize results"
    You should have a `*.srctrlprj` file corresponding to the project file and a `*.srctrldb` file for the DB. 
    Run `NumbatUI` or `Sourcetrail` on the project file. You can now navigate into the results.

    The user interface is described in depth in the [NumbatUI documentation](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#user-interface).
    Do not hesitate to take a look at  all the possibilities offered by NumbatUI, especially [Custom Trails](https://github.com/quarkslab/NumbatUI/blob/main/DOCUMENTATION.md#custom-trail-dialog).
!!! info
    The detailed documentation of each mapper is available in the [documentation](mappers/index.md).

--8<-- "README.md:publications"
--8<-- "README.md:authors"