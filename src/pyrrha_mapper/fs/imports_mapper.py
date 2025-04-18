# -*- coding: utf-8 -*-

#  Copyright 2023-2025 Quarkslab
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""Filesystem mapper based on Lief, which computes imports and exports."""

import logging
from pathlib import Path

import lief
from numbat import SourcetrailDB

from pyrrha_mapper.common import Binary, FileSystemMapper, Symbol
from pyrrha_mapper.exceptions import FsMapperError

lief.logging.disable()


class FileSystemImportsMapper(FileSystemMapper):
    """Filesystem mapper based on Lief, which computes imports and exports."""

    def __init__(self, root_directory: Path | str, db: SourcetrailDB | None):
        super(FileSystemImportsMapper, self).__init__(root_directory, db)

        if not self.dry_run_mode and self.db_interface is not None:
            # Setup graph customisation in NumbatUI
            self.db_interface.set_node_type("class", "Binaries", "binary")
            self.db_interface.set_node_type("typedef", "Symlinks", "symlink")
            self.db_interface.set_node_type("method", hover_display="exported function")
            self.db_interface.set_node_type("field", hover_display="exported symbol")

    @staticmethod
    def is_binary_supported(p: Path) -> bool:
        """Check if the path points on a supported file.

        It will return False if the path correspond to a symlink.
        :param p: the path of the file to analyzed
        :return: True is the path point on a file
        """
        return (
            p.is_file()
            and not p.is_symlink()
            and (lief.is_elf(str(p)) or lief.is_pe(str(p)))
        )

    @staticmethod
    def load_binary(root_directory: Path, file_path: Path) -> Binary:
        """Create a Binary object from a given file using lief.

        raise: FsMapperError if cannot load it
        """
        # compute absolute path but from root_directory base
        base = Path(root_directory.anchor)
        rel_path = base.joinpath(file_path.relative_to(root_directory))

        bin_obj = Binary(path=rel_path)
        is_elf = lief.is_elf(str(file_path))
        if is_elf:
            parser_config = lief.ELF.ParserConfig()
            if bin_obj.name.startswith("libcrypto"):
                parser_config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.HASH
            parsing_res: lief.ELF.Binary | None = lief.ELF.parse(
                str(file_path), parser_config
            )
            if parsing_res is None:
                raise FsMapperError(f"Lief cannot parse {file_path}")

            # parse imported libs
            for lib in parsing_res.libraries:
                bin_obj.add_imported_library_name(str(lib))

            # parse imported symbols
            for s in parsing_res.imported_symbols:
                bin_obj.add_imported_symbol_name(str(s.name))

            # parse exported symbols
            for s in parsing_res.exported_symbols:
                bin_obj.add_exported_symbol(
                    Symbol(
                        name=str(s.name),
                        is_func=s.is_function,
                        demangled_name=s.demangled_name,
                    )
                )

            # parse version requirements
            for req in parsing_res.symbols_version_requirement:
                for symb in req.get_auxiliary_symbols():
                    name = str(symb.name)
                    if name in bin_obj.version_requirement:
                        bin_obj.version_requirement[name].append(req.name)
                    else:
                        bin_obj.version_requirement[name] = [req.name]
        else:
            # PE parsing
            res: lief.PE.Binary | None = lief.PE.parse(str(file_path))
            if res is None:
                raise FsMapperError(f"Lief cannot parse {file_path}")
            # parse imported libs
            for lib in res.libraries:
                bin_obj.add_imported_library_name(str(lib))
            for f in res.imported_functions:
                bin_obj.add_imported_symbol_name(str(f.name))
            for f in res.exported_functions:
                bin_obj.add_exported_symbol(
                    Symbol(name=str(f.name), demangled_name=str(f.name), is_func=True)
                )

        return bin_obj

    def record_binary_in_db(self, binary: Binary) -> Binary:
        """Record the binary inside the DB as well as its internal symbols.

        Update 'bin_obj.id' with the id of the created object in DB and does the same
        thing for its symbol.
        :param binary: the Binary object to map
        :return: the updated object
        """
        # If dry run do not store the binary in DB
        if self.dry_run_mode or self.db_interface is None:
            return binary

        binary.id = self.db_interface.record_class(
            binary.name, prefix=f"{binary.path.parent}/", delimiter=":"
        )
        for symbol in binary.iter_exported_symbols():
            if symbol.is_func:
                symbol.id = self.db_interface.record_method(
                    symbol.name, parent_id=binary.id
                )
            else:
                symbol.id = self.db_interface.record_field(
                    symbol.name, parent_id=binary.id
                )
            if symbol.id is None:
                logging.error(
                    f"[bin mapping] Record of symbol '{symbol.name}' of binary \
'{binary.name}' failed."
                )
            else:
                self.db_interface.record_public_access(symbol.id)
        return binary
