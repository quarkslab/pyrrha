"""Filesystem mapper based on Lief, which computes imports and exports"""
import json
import logging
from dataclasses import dataclass
from pathlib import Path

import lief
from numbat import SourcetrailDB

from pyrrha_mapper.filesystem import Binary, FileSystemMapper

lief.logging.disable()


@dataclass
class ImportBinary(Binary):
    @staticmethod
    def is_supported(p: Path) -> bool:
        """
        Check if the given path points on a file (NOT via a symlink) which is
        of a format handled by this parser.
        :param p: the path of the file to analyzed
        :return: True is the path point on a file
        """
        return p.is_file() and not p.is_symlink() and (lief.is_elf(str(p)) or lief.is_pe(str(p)))

    def load(self):
        """
        parse the given path with lief to automatically fill the other fields
        at the exception done of the ids (the object should be put on a DB)
        """
        lief_obj: lief.Binary = lief.parse(str(self.file_path))
        is_elf = isinstance(lief_obj, lief.ELF.Binary)

        if is_elf:
            if self.name.startswith("libcrypto") and len(lief_obj.exported_functions) == 0:
                parser_config = lief.ELF.ParserConfig()
                parser_config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.HASH
                lief_obj = lief.ELF.parse(str(self.file_path), parser_config)

        # parse imported libs
        self.lib_names = lief_obj.libraries

        if is_elf:
            # parse imported symbols
            lief_obj: lief.ELF.Binary
            self.imported_symbols = [s.name for s in lief_obj.imported_symbols]

            # parse exported symbols
            for s in lief_obj.exported_symbols:
                if s.is_function:
                    self.exported_function_ids[s.name] = None
                else:
                    self.exported_symbol_ids[s.name] = None

            # parse version requirements
            for req in lief_obj.symbols_version_requirement:
                for symb in req.get_auxiliary_symbols():
                    if symb.name in self.version_requirement:
                        self.version_requirement[symb.name].append(req.name)
                    else:
                        self.version_requirement[symb.name] = [req.name]
        else:
            self.imported_symbols = [f.name for f in lief_obj.imported_functions]
            for s in lief_obj.exported_functions:
                self.exported_function_ids[s.name] = None

    def record_in_db(self, db: SourcetrailDB) -> None:
        """
        Record the binary inside the given db as well as its exported
        symbols/functions and its internal functions.
        Update 'self.id' with the id of the created object in DB as well as
        'self.exported_symbol/function_ids' and 'self.local_function_ids'
        dictionaries.
        :param db: DB interface
        """
        self.id = db.record_class(self.name, prefix=f"{self.fw_path.parent}/", delimiter=":")
        for name in self.exported_symbol_ids.keys():
            node_id = db.record_symbol_node(name, parent_id=self.id)
            db.record_public_access(node_id)
            self.exported_symbol_ids[name] = node_id
        for name in self.exported_function_ids.keys():
            node_id = db.record_method(name, parent_id=self.id)
            db.record_public_access(node_id)
            self.exported_function_ids[name] = node_id


class FileSystemImportsMapper(FileSystemMapper):
    BINARY_CLASS = ImportBinary

    def create_export(self):
        """Create a JSON export of the current Pyrrha results"""
        logging.debug("Start export")

        export = {"symlinks": dict(), "binaries": dict(), "symbols": dict()}
        for sym in self.symlink_paths.values():
            export["symlinks"][sym.id] = {"name": sym.path.name, "path": str(sym.path), "target_id": sym.target_id}

        for b in self.binary_paths.values():
            exported_symbol_ids = list(b.exported_symbol_ids.values()) + list(b.exported_function_ids.values())
            export["binaries"][b.id] = {
                "name": b.name,
                "path": str(b.fw_path),
                "export_ids": exported_symbol_ids,
                "imports": {
                    "lib": {
                        "ids": [str(lib.id) for lib in b.libs],
                        # keys are string so to keep type unicity
                        "non-resolved": b.non_resolved_libs,
                    },
                    "symbols": {"ids": b.imported_symbol_ids, "non-resolved": b.non_resolved_symbol_imports},
                },
            }
            for name, s_id in b.exported_symbol_ids.items():
                export["symbols"][s_id] = {"name": name, "is_func": False}
            for name, f_id in b.exported_function_ids.items():
                export["symbols"][f_id] = {"name": name, "is_func": True}

        logging.debug("Saving export")
        json_path = self.db_interface.path.with_suffix(".json")
        json_path.write_text(json.dumps(export))
        logging.info(f"Export saved: {json_path}")
