# Pyrrha Mappers

Pyrrha provides the following mappers:

- [`fs`](fs.md): a filesystem mapper. It maps  ELF/PE files, their imports and their exports.
 Also map symlinks which target ELF files.
- [`fs-cg`](fs-cg.md): a filesystem call graph mapper. It maps the whole firmware by interconnecting call graphs of all executables (requires disassembly).
