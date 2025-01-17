# Installation
The installation is done in two parts:

- installing `Pyrrha` (as a Python module);
- installing mappers external dependencies if required;
- installing `NumbatUI` to be able to visualize Pyrrha's results.

## NumbatUI Installation
NumbatUI should be compiled locally, as explained in its [README](https://github.com/quarkslab/NumbatUI/blob/main/README.md). For the moment it has only be tested on Ubuntu/Debian distributions. Here are the summarized compilation instructions:

**Prerequisites**
```commandline
apt-get update
apt-get install -y \
        cmake \
        git \
        build-essential \
        libboost-filesystem-dev libboost-program-options-dev libboost-system-dev libboost-date-time-dev \
        qt6-svg-dev qt6-base-dev qt6-5compat-dev \
        unzip wget \
        libclang-17-dev clang-17
```

**Compilation**
```commandline
git clone https://github.com/quarkslab/NumbatUI.git numbatui 
cd numbatui
mkdir -p build/Release 
cd build/Release
cmake -DCMAKE_BUILD_TYPE="Release" -DBUILD_CXX_LANGUAGE_PACKAGE=ON -DBUILD_PYTHON_LANGUAGE_PACKAGE=ON ../.. && make NumbatUI -j $(nproc)
```


## Pyrrha Installation
### Python Package
Pyrrha requires a Python version >= 3.10.
It is recommended to install the Python package inside a virtualenv. You can use `pip` to install it.
```python
pip install pyrrha-mapper
```
If you prefer using sources to install Pyrrha, do the following:
```commandline
# Do not forget to activate your virtualenv
pip install 'pyrrha @ git+https://github.com/quarkslab/pyrrha'

# If you prefer, you can manually clone the repository and then install the package
git clone https://github.com/quarkslab/pyrrha
cd pyrrha
pip install '.'
```

### External Dependencies

The `fs-cg` and the `exec-decomp` mappers require to have a proper installation of [Quokka](https://github.com/quarkslab/quokka) and so of IDA. The `exec-decomp` also requires to have an IDA license with decompiler.

The Quokka plugin for IDA can directly be downloaded from the [Release page](https://github.com/quarkslab/quokka/releases). The associated Python package is directly installed during Pyrrha Python package installation. 

!!! note
    The `fs-cg` and the `exec-decomp` mappers could be used without Quokka and IDA if you already have the cache files for your firmware (`.decompiled` and `.quokka` files). More details in the corresponding mapper documentation.

### Docker
`pyrrha` can be used with a docker. It provides Pyrrha, but you still need to install NumbatUI on your system as described in the [NumbatUI Installation](#numbatui-installation) section.

The docker image is directly available from our [Github registry](https://github.com/orgs/quarkslab/packages/container/package/pyrrha).


```commandline
cd ROOT_DIRECTORY/..
docker run  --rm -t -v $PWD:/tmp/pyrrha ghcr.io/quarkslab/pyrrha:latest fs [OPTIONS] ROOT_DIRECTORY
```

!!! warning
    The docker image has only be built for the `fs` mapper.

## Documentation

If you want to build the documentation, you need to install Pyrrha with the `[doc]` dependencies and then serve the documentation on a local server with `mkdocs`.

```bash
pip install 'pyrrha-mapper[doc]'

# serve doc locally
mkdocs serve
```