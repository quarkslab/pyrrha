# v0.3.0—Hack.lu edition
Version release at the occasion of the talk [Pyrrha: navigate easily into your system binaries](https://pretalx.com/hack-lu-2023/talk/WVFPNK/) given at the CTI-summit of Hack.lu.

**Full Changelog**: https://github.com/quarkslab/pyrrha/compare/v0.2.0...v0.3.0

## Features

File system parser:
* change JSON export structure

Documentation:
* add example of diffing using JSON export
* extend README to include new features

Docker/CI:
* Change base Docker image to a lighter one (`python` to `python-slim`)
* Add automatic build and upload of Docker image on Quarkslab's Github registry

## Fixes
None

## Associated Docker Image
Install from command line:
``` commandline
docker pull ghcr.io/quarkslab/pyrrha:v0.3.0
```
Use as base image in Dockerfile:
```dockerfile
FROM ghcr.io/quarkslab/pyrrha:v0.3.0
```

# v0.2.0

For more details, check [associated package page](https://github.com/quarkslab/pyrrha/pkgs/container/pyrrha/138112209?tag=v0.3.0).

## Features
CLI:
* setup logging and add debug option
* add `-h` option to show the usage (equivalent of `--help`)
* 
File system parser:
* add PE support (:warning: it is case sensitive for *all* imports (functions and libraries)
* add progress bar to show in real time percentage of wiles which have been indexed
* unresolved imports (lib and/or symbols) point now on non-indexed symbols to keep information in the database
* the mapping done by Pyrrha can be exported as a JSON file

Doc:
* add options to have real time Docker output in the terminal (for logs and progress bars)

## Fixes
* Dockerfile was copying non existing directory, this action has been removed.

# v0.1
First public release of Pyrrha