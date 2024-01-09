# Installation
The installation is done in two parts:

- installing `Pyrrha` (as a Python module);
- installing `Sourcetrail` to be able to visualize Pyrrha's results.

## Sourcetrail installation
Sourcetrail can be installed using [its last release](https://github.com/CoatiSoftware/Sourcetrail/releases/tag/2021.4.19) and its [documentation](https://github.com/CoatiSoftware/Sourcetrail/blob/master/DOCUMENTATION.md#installation).

## Pyrrha installation
### Python package
Pyrrha requires a Python version >= 3.10.
It is recommended to install the Python package inside a virtualenv. You can use `pip` to install it.
```python
pip install pyrrha-mapper
```
If you prefer using sources to install Pyrrha, do the following:
```commandline
# Do not forget to activate your virtualenv
$ pip install 'pyrrha @ git+https://github.com/quarkslab/pyrrha'

# If you prefer, you can manually clone the repository and then install the package
$ git clone https://github.com/quarkslab/pyrrha
$ cd pyrrha
$ pip install '.'
```

### Docker
`pyrrha` can be used with a docker. It provides Pyrrha, but you still need to install Sourcetrail on your system as described in the [Sourcetrail Installation](#sourcetrail-installation) section.

```commandline
$ cd ROOT_DIRECTORY/..
$ docker run  --rm -t -v $PWD:/tmp/pyrrha ghcr.io/quarkslab/pyrrha:latest fs [OPTIONS] ROOT_DIRECTORY
```

A docker image is directly available from our [Github registry](https://github.com/orgs/quarkslab/packages/container/package/pyrrha), but you can also build it from the sources.

```commandline
$ git clone PYRRHA_URL && cd pyrrha
$ docker build -t pyrrha .
```

## Documentation

If you want to build the documentation, you need to install Pyrrha with the `[doc]` dependencies and then serve the documentation on a local server with `mkdocs`.

```bash
pip install 'pyrrha-mapper[doc]'

# serve doc locally
mkdocs serve
```