# -*- coding: utf-8 -*-

#  Copyright 2023-2024 Quarkslab
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
"""Base classes for mapping binaries of a filesystem"""
import logging
import queue
from abc import abstractmethod, ABC
from dataclasses import dataclass, field
from multiprocessing import Pool, Queue, Manager
from pathlib import Path
from enum import Enum

from numbat import SourcetrailDB
from rich.progress import Progress


class ResolveDuplicateOption(Enum):
    IGNORE = 1
    ARBITRARY = 2
    INTERACTIVE = 3


@dataclass
class Binary(ABC):
    """
    Abstract class that represents a binary. It stores symbols/lib imported
    and exported
    The following methods should be implemented in its subclasses:
    - is_supported
    - load
    - record_in_db
    """

    file_path: Path
    fw_path: Path
    id: int = None
    lib_names: list[str] = field(default_factory=list)
    libs: list["Binary"] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)  # list(symbol names) symbols and functions
    imported_symbol_ids: list[int] = field(default_factory=list)
    non_resolved_libs: list[str] = field(default_factory=list)
    non_resolved_symbol_imports: list[str] = field(default_factory=list)
    exported_function_ids: dict[str, int | None] = field(default_factory=dict)  # dict(name, id)

    # ELF specific fields
    version_requirement: dict[str, list[str]] = field(default_factory=dict)  # dict(symbol_name, list(requirements))
    exported_symbol_ids: dict[str, int | None] = field(default_factory=dict)  # dict(name, id)

    @property
    def name(self):
        """:return: name of the binary without its path"""
        return self.file_path.name

    @staticmethod
    @abstractmethod
    def is_supported(p: Path) -> bool:
        """
        Check if the given path points on a file (NOT via a symlink) which is supported by the parser
        :param p: the path of the file to analyzed
        :return: True is the path point on a file
        """
        pass

    @abstractmethod
    def load(self):
        """
        parse the given path with lief to automatically fill the other fields
        at the exception done of the ids (the object should be put on a DB)
        """
        pass

    @abstractmethod
    def record_in_db(self, db: SourcetrailDB) -> None:
        """record the Binary and its components in the DB"""
        pass


@dataclass
class Symlink:
    """Class that represents a Symlink and store the associated DB id"""

    path: Path
    target_path: Path
    target_id: int
    id: int = None

    @property
    def name(self):
        """:return: name of the symlink without its path"""
        return self.path.name

    def record_in_db(self, db: SourcetrailDB) -> None:
        """
        Record the symlink inside the given db as its link to its target.
        Update 'self.id' with the id of the created object.
        :param db: DB interface
        """
        self.id = db.record_typedef_node(self.name, prefix=f"{self.path.parent}/", delimiter=":")
        db.record_ref_import(self.id, self.target_id)


def gen_fw_path(path: Path, root_directory: Path) -> Path:
    """
    Generate the path of a given file inside a firmware
    :param path: path of the file inside the local system
    :param root_directory: path of the virtual root of the firmware
    :return: path of the file inside the firmware
    """
    return Path(root_directory.anchor).joinpath(path.relative_to(root_directory))


# TODO FILESYSTEM


class FileSystemMapper(ABC):
    """
    Abstract class which is a base mapper to binaries of a filesystem.
    It maps a filesystem in the following order:
    - binaries
    - symlinks
    - lib imports
    - symbol_imports.
    To change the behavior of these mapping you can reimplement the
    map_* corresponding method.

    The following methods should be implemented:
    - create_export

    Warning: you can change the class used to represent a binary with the
    cls.BINARY_CLASS field.
    """

    BINARY_CLASS = Binary

    def __init__(self, root_directory: Path, db: SourcetrailDB):
        """
        :param root_directory: directory containing the filesystem to map
        :param db: interface to the DB
        """
        self.root_directory = root_directory.resolve().absolute()
        self.db_interface = db
        self.binaries: set[Path] = set(
            filter(lambda p: self.BINARY_CLASS.is_supported(p), self.root_directory.rglob("*"))
        )
        self.binary_names: dict[str, list[Binary]] = dict()
        self.binary_paths: dict[Path, Binary] = dict()
        self.symlinks: set[Path] = set(filter(lambda p: p.is_symlink(), self.root_directory.rglob("*")))
        self.symlink_names: dict[str, list[Symlink]] = dict()
        self.symlink_paths: dict[Path, Symlink] = dict()

        # Setup graph customisation in NumbatUI
        db.set_node_type("class", "Binaries", "binary")
        db.set_node_type("typedef", "Symlinks", "symlink")
        db.set_node_type("method", hover_display="exported function")
        db.set_node_type("field", hover_display="exported symbol")

    def gen_fw_path(self, path: Path) -> Path:
        """
        Generate the path of a given file inside a firmware
        :param path: path of the file inside the local system
        :return: path of the file inside the firmware
        """
        return gen_fw_path(path, self.root_directory)

    @classmethod
    def parse_binary_job(cls, ingress: Queue, egress: Queue, root_directory: Path) -> None:
        """
        Parse an executable file and create the associated Binary object.
        It is used for multiprocessing.
        :param ingress: input Queue, contain a Path
        :param egress: output Queue, send back (file path, Binary result or
        logging string if an issue happen)
        :param root_directory: path of the virtual root of the firmware
        """
        while True:
            try:
                path = ingress.get(timeout=0.5)
                try:
                    res = cls.BINARY_CLASS(path, gen_fw_path(path, root_directory))
                    res.load()
                except Exception as e:
                    res = e
                egress.put((path, res))
            except queue.Empty:
                pass
            except KeyboardInterrupt:
                break

    def map_binary(self, bin_object: Binary) -> None:
        """
        Given a Binary object add it to the DB.
        This function updates the fields 'self.binary_paths' and 'self.binary_names'
        which are respectively binary paths and names dictionaries pointing on
        the created Binary objects.
        :param bin_object: Binary object
        """
        bin_object.record_in_db(self.db_interface)
        self.binary_paths[bin_object.fw_path] = bin_object
        if bin_object.name in self.binary_names:
            self.binary_names[bin_object.name].append(bin_object)
        else:
            self.binary_names[bin_object.name] = [bin_object]

    def map_symlink(self, path) -> None:
        """
         Given a symlink, resolve it and if it points on a binary file, add it to the DB and create
         the associated Symlink object. Also add in db a link between the Symlink object
         and the Binary object corresponding to its target.
         This function updates the fields 'self.symlink_paths' and 'self.symlink_names'
         which are respectively symlink paths and names dictionaries pointing on
         the created Symlink objects.
        :param path: Symlink path
        """
        target = path.readlink()
        if not target.is_absolute():
            target = path.resolve()
            if not target.is_relative_to(self.root_directory):
                logging.warning(
                    f"[symlinks] cannot resolve '{path.name}': path '{target}' does not exist in {self.root_directory}"
                )
                return
            if not target.exists():
                target = self.gen_fw_path(target)
                logging.warning(f"[symlinks] path {target} does not exist")
                return
            if not self.BINARY_CLASS.is_supported(target):
                target = self.gen_fw_path(target)
                logging.debug(f"path {target} does not correspond to a supported binary")
                return
            target = self.gen_fw_path(target)
        elif target == Path("/dev/null"):
            logging.debug(f"[symlinks] '{path.name}': path '{path}' points on '/dev/null'")
            return
        elif not target.exists():
            logging.warning(f"[symlinks] path {target} does not exist")
            return
        elif not self.BINARY_CLASS.is_supported(target):
            logging.debug(f"path {target} does not correspond to a supported binary")
            return
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
            logging.warning(
                f"[symlinks] cannot resolve '{path.name}': path '{target}' does not correspond to a recorded binary"
            )

    def map_lib_imports(self, binary, resolve_duplicate_imports=ResolveDuplicateOption.IGNORE) -> None:
        """
        Given an already mapped binary, resolve its library
        imports using the following heuristics:
         - look for a binary which have the looked name, if there is a match,
           it is considered as solved, if there is several matches, no mapping is
           done and a warning log is printed
         - if no binary match, the same heuristics are applied to symlinks
        This function update the DB with the import links found and each binary's
        'imported libs' field with the corresponding ElfBinary objects (or the
        targeted Binary object in the case of a Symlink)
        """
        for lib_name in binary.lib_names:
            if lib_name in self.binary_names:
                if len(self.binary_names[lib_name]) > 1 and resolve_duplicate_imports is ResolveDuplicateOption.IGNORE:
                    logging.warning(
                        f"[lib imports] {binary.fw_path}: several matches for importing lib {lib_name}, not put into DB"
                    )
                else:
                    to_import = None
                    if (
                        len(self.binary_names[lib_name]) > 1
                        and resolve_duplicate_imports is ResolveDuplicateOption.INTERACTIVE
                    ):
                        while to_import is None or to_import < 0 or to_import >= len(self.binary_names[lib_name]):
                            print(f"several matches for importing lib {lib_name}, choose one to keep\n")
                            for i in range(len(self.binary_names[lib_name])):
                                print(f"{i}: {self.binary_names[lib_name][i].file_path}")
                            try:
                                to_import = int(input())
                            except ValueError:
                                print("Enter a valid number")
                    else:  # "arbitrary" option
                        to_import = 0
                    lib_obj = self.binary_names[lib_name][to_import]
                    self.db_interface.record_ref_import(binary.id, lib_obj.id)
                    binary.libs.append(lib_obj)
            elif lib_name in self.symlink_names:
                if len(self.symlink_names[lib_name]) > 1 and resolve_duplicate_imports is ResolveDuplicateOption.IGNORE:
                    logging.warning(
                        f"[lib imports] {binary.fw_path}: several matches for importing lib {lib_name}, not put into DB"
                    )
                else:
                    to_import = None
                    if (
                        len(self.symlink_names[lib_name]) > 1
                        and resolve_duplicate_imports is ResolveDuplicateOption.INTERACTIVE
                    ):
                        while to_import is None or to_import < 0 or to_import >= len(self.symlink_names[lib_name]):
                            print(f"several matches for importing lib {lib_name}, choose one to keep\n")
                            for i in range(len(self.symlink_names[lib_name])):
                                print(f"{i}: {self.symlink_names[lib_name][i].target_path}")
                            try:
                                to_import = int(input())
                            except ValueError:
                                print("Enter a valid number")
                    else:  # "arbitrary" option
                        to_import = 0
                    sym_obj = self.symlink_names[lib_name][to_import]
                    self.db_interface.record_ref_import(binary.id, sym_obj.id)
                    binary.libs.append(self.binary_paths[sym_obj.target_path])
            else:
                logging.debug(f"[lib imports] {binary.fw_path}: lib '{lib_name}' not found in DB")
                lib_id = self.db_interface.record_class(lib_name, is_indexed=False)
                self.db_interface.record_ref_import(binary.id, lib_id)
                binary.non_resolved_libs.append(lib_name)

    def map_symbol_imports(self, binary: Binary, resolve_duplicate_imports=ResolveDuplicateOption.IGNORE) -> None:
        """
        Given an already mapped binary, resolve its symbols.
        This function update the DB with the import links found.
        """
        for func_name in binary.imported_symbols:
            if len(func_name.split("@@")) == 2:  # symbols with a specific version
                symb_name, symb_version = func_name.split("@@")
                if symb_version in binary.version_requirement:
                    for lib_name in binary.version_requirement[symb_version]:
                        if lib_name not in self.binary_names:
                            logging.debug(f"[symbol imports] {binary.fw_path}: lib '{lib_name}' not found in DB")
                            lib_id = self.db_interface.record_class(lib_name, is_indexed=False)
                            symb_id = self.db_interface.record_field(symb_name, parent_id=lib_id, is_indexed=False)
                            self.db_interface.record_ref_import(binary.id, symb_id)
                            binary.non_resolved_symbol_imports.append(func_name)
                        elif (
                            len(self.binary_names[lib_name]) > 1
                            and resolve_duplicate_imports is ResolveDuplicateOption.IGNORE
                        ):
                            logging.warning(
                                f"[symbol imports] {binary.fw_path}: several matches for importing lib {lib_name}, not put into DB"
                            )
                        else:
                            to_import = None
                            if (
                                len(self.binary_names[lib_name]) > 1
                                and resolve_duplicate_imports is ResolveDuplicateOption.INTERACTIVE
                            ):
                                while (
                                    to_import is None or to_import < 0 or to_import >= len(self.binary_names[lib_name])
                                ):
                                    print(f"several matches for importing lib {lib_name}, choose one to keep\n")
                                    for i in range(len(self.binary_names[lib_name])):
                                        print(f"{i}: {self.binary_names[lib_name][i].file_path}")
                                    try:
                                        to_import = int(input())
                                    except ValueError:
                                        print("Enter a valid number")
                            else:  # "arbitrary" option
                                to_import = 0
                            lib: Binary = self.binary_names[lib_name][to_import]
                            if symb_name in lib.exported_symbol_ids:
                                symb_id = lib.exported_symbol_ids[symb_name]
                                self.db_interface.record_ref_import(binary.id, symb_id)
                                binary.imported_symbol_ids.append(symb_id)
                            elif symb_name in lib.exported_function_ids:
                                symb_id = lib.exported_function_ids[symb_name]
                                self.db_interface.record_ref_import(binary.id, symb_id)
                                binary.imported_symbol_ids.append(symb_id)
                            else:
                                symb_id = self.db_interface.record_field(symb_name, parent_id=lib.id, is_indexed=False)
                                self.db_interface.record_ref_import(binary.id, symb_id)
                                binary.non_resolved_symbol_imports.append(func_name)
            else:
                found = False
                for lib in binary.libs:
                    if func_name in lib.exported_symbol_ids:
                        symb_id = lib.exported_symbol_ids[func_name]
                        self.db_interface.record_ref_import(binary.id, symb_id)
                        binary.imported_symbol_ids.append(symb_id)
                        found = True
                        break
                    elif func_name in lib.exported_function_ids:
                        symb_id = lib.exported_function_ids[func_name]
                        self.db_interface.record_ref_import(binary.id, symb_id)
                        binary.imported_symbol_ids.append(symb_id)
                        found = True
                        break
                if found is False:
                    logging.debug(f"[symbol imports] {binary.name}: cannot resolve {func_name}")
                    symb_id = self.db_interface.record_field(func_name, is_indexed=False)
                    self.db_interface.record_ref_import(binary.id, symb_id)
                    binary.non_resolved_symbol_imports.append(func_name)

    @abstractmethod
    def create_export(self):
        """Abstract class which should be implemented in order to know how
        to export the current pyrrha results"""
        pass

    def map(self, threads: int, export: bool = False, resolve_duplicate_imports=ResolveDuplicateOption.IGNORE) -> None:
        """
        Map all the content of 'self.root_directory', in the order:
        - binaries;
        - symlinks (and resolve them);
        - lib imports;
        - symbol imports.
        It updates the fields and the DB
        :param threads: number of threads to use
        :param export: if True create a JSON export of the mapping. It will be stored
            at the same place as the DB (file name: DB_NAME.json)
        :param resolve_duplicate_imports: the chosen option for duplicate import resolution
        """
        with Progress() as progress:

            binaries_map = progress.add_task("[deep_pink2]Binaries mapping", total=len(self.binaries))
            symlinks_map = progress.add_task("[orange_red1]Symlinks mapping", total=len(self.symlinks))
            lib_imports = progress.add_task("[orange1]Library imports mapping", total=len(self.binaries))
            symbol_imports = progress.add_task("[gold1]Symbol imports mapping", total=len(self.binaries))

            # Parse binaries
            logging.debug(f"[main] Start Binaries parsing: {len(self.binaries)} binaries to parse")
            if threads > 1:  # multiprocessed case
                manager = Manager()
                ingress = manager.Queue()
                egress = manager.Queue()
                pool = Pool(threads)

                # Launch all workers and fill input queue
                for _ in range(threads - 1):
                    pool.apply_async(self.parse_binary_job, (ingress, egress, self.root_directory))
                for path in self.binaries:
                    ingress.put(path)
                logging.debug(f"[main] {threads - 1} threads created")

                i = 0
                while True:
                    path, res = egress.get()
                    i += 1
                    if isinstance(res, self.BINARY_CLASS):
                        self.map_binary(res)
                    else:
                        logging.warning(f"Error while parsing {path}: {res}")
                    progress.update(binaries_map, advance=1)
                    if i == len(self.binaries):
                        break
                pool.terminate()
            else:
                logging.debug("[main] One thread mode")
                for path in self.binaries:
                    self.map_binary(self.BINARY_CLASS(path, self.gen_fw_path(path)))
                    progress.update(binaries_map, advance=1)
            self.db_interface.commit()

            # Parse and resolve symlinks
            logging.debug(f"[main] Start Symlinks parsing: {len(self.symlinks)} symlinks to parse")
            for path in self.symlinks:
                self.map_symlink(path)
                progress.update(symlinks_map, advance=1)
            self.db_interface.commit()

            # Handle imports
            logging.debug("[main] Start Libraries imports resolution")
            for binary in self.binary_paths.values():
                self.map_lib_imports(binary, resolve_duplicate_imports)
                progress.update(lib_imports, advance=1)
            self.db_interface.commit()
            logging.debug(f"[main] Start Symbols imports resolution")
            for binary in self.binary_paths.values():
                self.map_symbol_imports(binary, resolve_duplicate_imports)
                progress.update(symbol_imports, advance=1)
            self.db_interface.commit()

            if export:
                self.create_export()
