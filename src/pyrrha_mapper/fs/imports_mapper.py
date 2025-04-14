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

from pathlib import Path

import lief

from pyrrha_mapper.exceptions import FsMapperError

from pyrrha_mapper import Binary, FileSystem, Symbol, FileSystemMapper

lief.logging.disable()


class FileSystemImportsMapper(FileSystemMapper):
    """Filesystem mapper based on Lief, which computes imports and exports."""

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
        bin_obj = Binary(
            file_path=file_path, path=FileSystem.gen_fw_path(file_path, root_directory)
        )
        is_elf = lief.is_elf(str(file_path))
        if is_elf:
            parser_config = lief.ELF.ParserConfig()
            if bin_obj.name.startswith("libcrypto"):
                parser_config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.HASH
            parsing_res: lief.ELF.Binary | None = lief.ELF.parse(
                str(bin_obj.file_path), parser_config
            )
            if parsing_res is None:
                raise FsMapperError(f"Lief cannot parse {bin_obj.file_path}")

            # parse imported libs
            for lib in parsing_res.libraries:
                bin_obj.add_imported_library_name(str(lib))

            # parse imported symbols
            for s in parsing_res.imported_symbols:
                bin_obj.add_imported_symbol_name(str(s.name))

            # parse exported symbols
            for s in parsing_res.exported_symbols:
                bin_obj.add_exported_symbol(
                    Symbol(name=str(s.name), is_func=s.is_function)
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
            res: lief.Binary | None = lief.parse(str(bin_obj.file_path))
            if res is None:
                raise FsMapperError(f"Lief cannot parse {bin_obj.file_path}")
            # parse imported libs
            for lib in res.libraries:
                bin_obj.add_imported_library_name(str(lib))
            for f in res.imported_functions:
                bin_obj.add_imported_symbol_name(str(f.name))
            for f in res.exported_functions:
                bin_obj.add_exported_symbol(Symbol(name=str(f.name), is_func=True))

        return bin_obj

    def record_binary_in_db(self, binary: Binary) -> Binary:
        """Record the binary inside the DB as well as its internal symbols.

        Update 'bin_obj.id' with the id of the created object in DB and does the same
        thing for its symbol.
        :param binary: the Binary object to map
        :return: the updated object
        """
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
            self.db_interface.record_public_access(symbol.id)
        return binary
