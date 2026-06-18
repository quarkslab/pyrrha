## Unreleased

### Features
- All mappers now share a single disassembler `--backend` value (`ida`/`ghidra`) implemented in one common place, replacing the previous per-mapper disassembler/exporter selection.
- Remove the `qbinary`/Quokka dependency: `fs-cg` and `decomp` now interact directly with the disassemblers (IDA, Ghidra), so Pyrrha can run on systems without Quokka.
- Add ELF SONAME support: binaries are indexed by their `DT_SONAME` so imports referencing a SONAME resolve even without a matching symlink.
- `decomp` mapper: full rework around a class-based object integrated with the common backend layer.
- `decomp` mapper: add a `-e/--export` option to dump the result as JSON, loadable through the new `ExportedDecompilation` object exposed by Pyrrha.
- Expose `Binary` image base and relocatable information on the internal representation.
- Improve the documentation (installation, quick summary, decomp mapper) and add unit tests for the `decomp` export model plus functional tests for the `decomp` mapper.

### Fixes
- `intercg` mapper: various fixes around addresses and demangled names, missing Ghidra thunks, extended ignore list, and argument renaming.
- `fs-cg` mapper: avoid an infinite loop in trampoline resolution and add a real timeout to program loading.
- `fs`/`fs-cg` mappers: pass `load_binary` arguments through a `partial` mechanism and improve multiprocessing error handling.
- `decomp` mapper: fix the mapping run (`map` now reports success/failure, runs the decompilation and call-graph indexing phases, and records the binary node so functions get a valid parent).
- `decomp` mapper: fix call-graph source cross-references (call-site locations are looked up by callee address and no longer raise on the first reference).
- `decomp` mapper: fix command-line arguments and improve the decompilation script (correct `NamedTemporaryFile` usage, better IDA decompilation output).
- `decomp` mapper (IDA backend): use the `ida_domain` 0.5.0 pseudocode API (`get_pseudocode(func).to_text(...)`), fixing a `TypeError` that broke every IDA decompilation run.
- `decomp` mapper: skip imported functions during source and call-graph indexing (they have no decompiled body), removing spurious per-function error/warning logs.
- `decomp` mapper: write decompiled source via a portable temporary file, fixing a `TypeError` (`delete_on_close`) that aborted every run on Python 3.11.
- `decomp` mapper: attach call-site locations to the call reference returned by `record_ref_call` instead of the callee symbol id.
- `decomp` mapper: record each function's source file under a per-function unique name, fixing a `UNIQUE constraint failed: file.id` crash when two functions share a name.
- `cli`: keep an existing suffix in the DB path and annotate the `decomp` mapper variable with its base type to fix a type-checking error.

### Internal
- Reorganize the repository into two submodules (`backend` and `mappers`) and rework the mappers so backend support lives in a single common place; remove unused modules and the `heimdallr`/disassembly-sync prototype.
- CI: build and test IDA and Ghidra Docker images, run the `decomp` export-model and functional tests, export test artifacts, and trigger builds only on relevant changes.
- Add backend-free unit tests for the `decomp` mapper's recording, source-indexing and call-graph logic, raising its coverage without a disassembler.

## v1.0.1—Improve exe-decomp mapper

### Features
- doc: setup multi version doc
- doc: update doc for last version of mappers

### Fixes

- `exe-decomp` mapper: increase IDA timeout and use `TempFile` to be multiplatform compatible
- `exe-decomp` mapper: improve resolution of calls

**Full Changelog**: [https://github.com/quarkslab/pyrrha/compare/v1.0.0...v1.0.1](https://github.com/quarkslab/pyrrha/compare/v1.0.0...v1.0.1)


## v1.0.0—New mappers

### Features
- Add two new mappers: `fs-cg` and `exe-decomp`.
- Rework internal representation of filesystem and binaries.
- `fs` and `fs-cg` results could be exported and then loaded/manipulated trough the `FileSystem` object now exposed by Pyrrha.
- Add unit tests for internal data structures and `fs`/`fs-cg` mappers.

### Fixes

- Various fixes following tests, check changelog for details.

**Full Changelog**: [https://github.com/quarkslab/pyrrha/compare/v0.4.3...v1.0.0](https://github.com/quarkslab/pyrrha/compare/v0.4.3...v1.0.0)

## v0.4.3—Resolution Strategies

### Features
File system parser:

* Add duplicate import resolution strategies: the user can now choose between three strategies (`--ignore`, `--arbitrary`, `--interactive`).
* Add customization into the resulting graph (NumbatUI features, which is currently under active development).
* Rework internal mapper architecture.

### Fixes
File system parser:

- Fix the path resolution issues when firmware path contains `..`

**Full Changelog**: [https://github.com/quarkslab/pyrrha/compare/v0.4.2...v0.4.3](https://github.com/quarkslab/pyrrha/compare/v0.4.2...v0.4.3)


## v0.4.2—Documentation
This version introduces a brand new documentation and some uniformization to help future mapper development.

### Features
All:

* A new documentation

File system parser:

* Deactivate lief logging to reduce "noise".

Docker/CI:

* Add template for future mapper.

**Full Changelog**: [https://github.com/quarkslab/pyrrha/compare/v0.4.1...v0.4.2](https://github.com/quarkslab/pyrrha/compare/v0.4.1...v0.4.2)

## v0.4.1
This version enforces the usage of a more efficient version of numbat and fixes some little bugs.

### Features
All:

- enforce numbat >= 0.2 to increase analysis speed

### Fixes
File system parser:

- check db existence with the appropriate numbat method
- remove error-prone path modifications in symlink resolution

**Full Changelog**: [https://github.com/quarkslab/pyrrha/compare/v0.4.0...v0.4.1](https://github.com/quarkslab/pyrrha/compare/v0.4.0...v0.4.1)

## v0.4.0—Numbat version
This version introduces the usage of Numbat, our home-made Sourcetrail SDK fully Pythonic. Thanks to it, `pyrrha` is much easier to install.

### Features
All:

* Remove SourcetrailDB dependency to use `numbat` library

File system parser:

* multiprocess binary parsing (lief export)

Docker/CI:

* Adapt to numbat dependency. Remove all the useless installations.
* Add package publication on pypi.

### :warning: Important Changes
- Package name was changes into `pyrrha-mapper` as the `pyrrha` package already exists on Pypi.

### Fixes
- Symlink resolution was partially broken due to not extensive checks on the path. It was trying to parse directory for example.

### Associated Python package
This release contains a CI that automatically upload the package on Pypi. You can now install Pyrrha by doing
```python
pip install pyrrha-mapper
```

**Full Changelog**: [https://github.com/quarkslab/pyrrha/compare/v0.3.0...v0.4.0](https://github.com/quarkslab/pyrrha/compare/v0.3.0...v0.4.0)

## v0.3.0—Hack.lu edition
Version release at the occasion of the talk [Pyrrha: navigate easily into your system binaries](https://pretalx.com/hack-lu-2023/talk/WVFPNK/) given at the CTI-summit of Hack.lu.

**Full Changelog**: https://github.com/quarkslab/pyrrha/compare/v0.2.0...v0.3.0

### Features

File system parser:

* change JSON export structure

Documentation:

* add example of diffing using JSON export
* extend README to include new features

Docker/CI:

* Change base Docker image to a lighter one (`python` to `python-slim`)
* Add automatic build and upload of Docker image on Quarkslab's Github registry

### Fixes
None

### Associated Docker Image
Install from command line:
``` commandline
docker pull ghcr.io/quarkslab/pyrrha:v0.3.0
```
Use as base image in Dockerfile:
```dockerfile
FROM ghcr.io/quarkslab/pyrrha:v0.3.0
```

## v0.2.0

For more details, check [associated package page](https://github.com/quarkslab/pyrrha/pkgs/container/pyrrha/138112209?tag=v0.3.0).

### Features
CLI:

* setup logging and add debug option
* add `-h` option to show the usage (equivalent of `--help`)

File system parser:

* add PE support (:warning: it is case sensitive for *all* imports (functions and libraries)
* add progress bar to show in real time percentage of wiles which have been indexed
* unresolved imports (lib and/or symbols) point now on non-indexed symbols to keep information in the database
* the mapping done by Pyrrha can be exported as a JSON file

Doc:

* add options to have real time Docker output in the terminal (for logs and progress bars)

### Fixes
* Dockerfile was copying non existing directory, this action has been removed.

## v0.1
First public release of Pyrrha
