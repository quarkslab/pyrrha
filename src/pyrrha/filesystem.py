# -*- coding: utf-8 -*-

#  Copyright 2023 Quarkslab
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

from dataclasses import dataclass, field
from pathlib import Path

import lief

from .db import DBInterface


@dataclass
class ELFBinary:
    file_path: Path
    fw_path: Path
    id: int = None
    imported_lib_names: list[str] = field(default_factory=list)
    imported_libs: list['ELFBinary'] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)  # list(symbol names) symbols and functions
    version_requirement: dict[str, list[str]] = field(default_factory=dict)  # dict(symbol_name, list(requirements))
    exported_symbol_ids: dict[str, int] = field(default_factory=dict)  # dict(name, id)
    exported_function_ids: dict[str, int] = field(default_factory=dict)  # dict(name, id)

    def __post_init__(self):
        """
        parse the given path with lief to automatically fill the other fields
        at the exception done of the ids (the object should be put on a DB)
        """
        if self.name == 'libcrypto.so.1.1':
            lief_obj = lief.ELF.parse(str(self.file_path), lief.ELF.DYNSYM_COUNT_METHODS.HASH)
        else:
            lief_obj = lief.ELF.parse(str(self.file_path))

        # parse imported libs/symbols
        self.imported_lib_names = lief_obj.libraries
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

    @property
    def name(self):
        return self.file_path.name

    def record_in_db(self, db: DBInterface) -> None:
        """
        Record the binary inside the given db as well as its exported
        symbols/functions.
        Update 'self.id' with the id of the created object in DB as well as
        'self.exported_symbol/function_ids' dictionaries.
        :param db: DB interface
        """
        self.id = db.record_binary_file(self.fw_path)
        for name in self.exported_symbol_ids.keys():
            self.exported_symbol_ids[name] = db.record_exported_symbol(self.fw_path, name, is_function=False)
        for name in self.exported_function_ids.keys():
            self.exported_function_ids[name] = db.record_exported_symbol(self.fw_path, name, is_function=True)


@dataclass
class Symlink:
    path: Path
    target_path: Path
    target_id: int
    id: int = None

    @property
    def name(self):
        return self.path.name

    def record_in_db(self, db: DBInterface) -> None:
        """
        Record the symlink inside the given db as its link to its target.
        Update 'self.id' with the id of the created object.
        :param db: DB interface
        """
        self.id = db.record_symlink(self.path)
        db.record_symlink_target(self.id, self.target_id)


class FileSystemMapper:
    def __init__(self, root_directory: Path, db: DBInterface):
        """
        :param root_directory: directory containing the filesystem to map
        :param db: interface to the DB
        """
        self.root_directory = root_directory
        self.db_interface = db
        self.binary_names: dict[str, list[ELFBinary]] = dict()
        self.binary_paths: dict[Path, ELFBinary] = dict()
        self.symlink_names: dict[str, list[Symlink]] = dict()
        self.symlink_paths: dict[Path, Symlink] = dict()

    def gen_fw_path(self, path: Path) -> Path:
        """
        Generate the path of a given file inside a firmware
        :param path: path of the file inside the local system
        :return: path of the file inside the firmware
        """
        return Path(self.root_directory.anchor).joinpath(path.relative_to(self.root_directory))

    def _map_binaries(self) -> None:
        """
        Iterate all the subdirectories of 'self.root_dir' to find all the binaries.
        Add them to the DB and create the associated ELFBinary objects.
        This function updates the fields 'self.binary_paths' and 'self.binary_names'
        which are respectively binary paths and names dictionaries pointing on
        the created ELFBinary objects.
        It adds the binaries into the DB.
        """
        for path in filter(lambda p: p.is_file() and not p.is_symlink() and lief.is_elf(str(p)),
                           self.root_directory.rglob('*')):
            elf_object = ELFBinary(path, self.gen_fw_path(path))
            elf_object.record_in_db(self.db_interface)
            self.binary_paths[elf_object.fw_path] = elf_object
            if elf_object.name in self.binary_names:
                self.binary_names[elf_object.name].append(elf_object)
            else:
                self.binary_names[elf_object.name] = [elf_object]

    def _map_symlinks(self) -> None:
        """
        Iterate all the subdirectories of 'self.root_dir' to find all the symlinks.
        Resolve them and if they point on an ELF file, add them to the DB and create
        the associated Symlink objects. Also add in db a link between the Symlink object
        and the ELFBinary object corresponding to its target.
        This function updates the fields 'self.symlink_paths' and 'self.symlink_names'
        which are respectively symlink paths and names dictionaries pointing on
        the created Symlink objects.
        It adds the Symlinks into the DB.
        """
        for path in filter(lambda p: p.is_symlink(), self.root_directory.rglob('*')):
            target = path.readlink()
            if not target.is_absolute():
                target = path.resolve()
                if not target.is_file() or not lief.is_elf(str(target)):
                    continue
                elif not target.is_relative_to(self.root_directory):
                    print(f"cannot resolve '{path.name}': path '{target} does not exist in {self.root_directory}'")
                    continue
                target = self.gen_fw_path(target)
            elif target == Path('/dev/null'):
               # print(f"'{path.name}': path '{path}' points on '/dev/null'")
                continue
            if target in self.binary_paths:
                target_obj = self.binary_paths[target]
                path = self.gen_fw_path(path)
                symlink_obj = Symlink(path, target_obj.fw_path, target_obj.id)
                symlink_obj.record_in_db(self.db_interface)
                self.symlink_paths[path] = symlink_obj
                if symlink_obj.name in self.symlink_names:
                    self.symlink_names[symlink_obj.name].append(symlink_obj)
                else:
                    self.symlink_names[symlink_obj.name] = [symlink_obj]
            else:
                print(f"cannot resolve '{path.name}': path '{target} does not correspond to a recorded binaries'")

    def _map_lib_imports(self) -> None:
        """
        Iterate over all the binaries (already mapped) and resolve there library
        imports using the following heuristics:
         - look for a binary which have the looked name, if there is a match,
           it is considered as solved, if there is several matches, no mapping is
           done and a warning log is printed
         - if no binary match, the same heuristics are applied to symlinks
        This function update the DB with the import links found and each binary's
        'imported libs' field with the corresponding ElfBinary objects (or the
        targeted ELFBinary object in the case of a Symlink)
        """
        for path, binary in self.binary_paths.items():
            for lib_name in binary.imported_lib_names:
                if lib_name in self.binary_names:
                    if len(self.binary_names[lib_name]) != 1:
                        print(f"[lib imports] {path}: several matches for importing lib {lib_name}, not put into DB")
                    else:
                        lib_obj = self.binary_names[lib_name][0]
                        self.db_interface.record_import(binary.id, lib_obj.id)
                        binary.imported_libs.append(lib_obj)
                elif lib_name in self.symlink_names:
                    if len(self.symlink_names[lib_name]) != 1:
                        print(f"[lib imports] {path}: several matches for importing lib {lib_name}, not put into DB")
                    else:
                        sym_obj = self.symlink_names[lib_name][0]
                        self.db_interface.record_import(binary.id, sym_obj.id)
                        binary.imported_libs.append(self.binary_paths[sym_obj.target_path])
                else:
                    print(f"[lib imports] {path}: lib '{lib_name}' not found in DB")

    def _map_symbol_imports(self) -> None:
        """
        Iterate over all the binaries (already mapped) and resolve their symbols.
        This function update the DB with the import links found.
        """
        for path, binary in self.binary_paths.items():
            for func_name in binary.imported_symbols:
                found = False
                if len(func_name.split('@@')) == 2:  # symbols with a specific version
                    symb_name, symb_version = func_name.split('@@')
                    if symb_version in binary.version_requirement:
                        for lib_name in binary.version_requirement[symb_version]:
                            if lib_name not in self.binary_names:
                                print(f"[symbol imports] {path}: lib '{lib_name}' not found in DB")
                            elif len(self.binary_names[lib_name]) > 1:
                                print(
                                    f"[symbol imports] {path}: several matches for importing lib {lib_name}, not put into DB")
                            else:
                                lib = self.binary_names[lib_name][0]
                                if symb_name in lib.exported_symbol_ids:
                                    self.db_interface.record_import(binary.id, lib.exported_symbol_ids[symb_name])
                                    found = True
                                elif symb_name in lib.exported_function_ids:
                                    self.db_interface.record_import(binary.id, lib.exported_function_ids[symb_name])
                                    found = True
                else:
                    for lib in binary.imported_libs:
                        if func_name in lib.exported_symbol_ids:
                            self.db_interface.record_import(binary.id, lib.exported_symbol_ids[func_name])
                            found = True
                            break
                        elif func_name in lib.exported_function_ids:
                            self.db_interface.record_import(binary.id, lib.exported_function_ids[func_name])
                            found = True
                            break
                if found is False:
                    print(f"[symbol imports] {binary.name}: cannot resolve {func_name}")

    def map(self) -> None:
        """
        Map all the content of 'self.root_directory', in the order:
        - binaries;
        - symlinks (and resolve them);
        - lib imports;
        - symbol imports.
        It updates the fields and the DB
        """
        self._map_binaries()
        print('[map] Binaries mapping done.')
        self._map_symlinks()
        print('[map] Symlinks mapping done.')
        self._map_lib_imports()
        print("[map] Binaries' lib imports mapping done.")
        self._map_symbol_imports()