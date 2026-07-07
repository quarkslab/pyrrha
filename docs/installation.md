# Installation
The installation is done in three parts:

- installing **Pyrrha** (as a Python module);
- installing **NumbatUI** to be able to visualize Pyrrha's results.

!!! info
    It is also possible to visualize results with **Sourcetrail**, it is the base from which **NumbatUI** was forked. The user won't be able to use new features like the renaming of the nodes.


## Pyrrha Installation

!!! note ""
    <!-- === ":fontawesome-brands-python: Python Package" -->
        **Pyrrha** relies on a backend (IDA or Ghidra) to generate its results, except for the light mapper `fs`. This installation is not covered here, we consider the following prerequisites:

        - Python **≥ 3.10**.
        - A local installation of **IDA Pro 9.1+** and/or **Ghidra 12.0+** —
            required by the InterCG mapper.

        Then you can install **Pyrrha** Python package in a virtual environment with `pip`.
        ```sh
        # Do not forget to activate your virtualenv
        pip install pyrrha-mapper 
        ```
        If you prefer using sources to install Pyrrha, do the following:
        ```sh
        # Do not forget to activate your virtualenv
        pip install 'pyrrha @ git+https://github.com/quarkslab/pyrrha'
        ```
    <!-- === ":fontawesome-brands-docker: Docker Image"
        **Pyrrha** can be used with a docker. It provides **Pyrrha** with a backend (**Ghidra**), but you still need to install NumbatUI on your system as described in the [**NumbatUI** Installation](#numbatui-installation) section.

        The docker image is directly available from our [Github registry](https://github.com/orgs/quarkslab/packages/container/package/pyrrha).


        ```commandline
        cd ROOT_DIRECTORY/..
        docker run  --rm -t -v $PWD:/tmp/pyrrha ghcr.io/quarkslab/pyrrha:latest MAPPER [OPTIONS] ROOT_DIRECTORY
        ```

         -->


## Visualizer Installation

!!! note ""
    === "**NumbatUI**"
        <a name="numbatui-installation"></a>
        For Debian like distribution, download the [`.deb`](https://github.com/quarkslab/NumbatUI/releases) package and install it on your system (`sudo dpkg -i numbatui.deb`)

        For other systems, you can also compile it manually or use a Docker, check [NumbatUI documentation](https://quarkslab.github.io/NumbatUI/installation/) for further details.
        
    === "**Sourcetrail**"
        === "Linux"
            ```sh
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

## Documentation

If you want to build the documentation, you need to install Pyrrha with the `[doc]` dependencies and then serve the documentation on a local server with `zensical`.

```bash
pip install 'pyrrha-mapper[doc]'

# serve doc locally
zensical serve
```