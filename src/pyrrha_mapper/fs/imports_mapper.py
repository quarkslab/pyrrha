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
import queue
from abc import ABC
from dataclasses import dataclass
from multiprocessing import Queue, get_context
from pathlib import Path
from typing import Any

import lief
from numbat import SourcetrailDB
from rich.progress import Progress

from pyrrha_mapper.common import Binary, FileSystem, FileSystemMapper, Symbol, Symlink
from pyrrha_mapper.types import ResolveDuplicateOption

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
        return p.is_file() and not p.is_symlink() and (lief.is_elf(str(p)) or lief.is_pe(str(p)))

    @staticmethod
    def load_binary(root_directory: Path, file_path: Path) -> tuple[Binary, Any] | str:
        """Create a Binary object from a given file using lief.

        raise: FsMapperError if cannot load it
        :return: bin object and additionnal info if needed or a string in case of error
        """
        # compute absolute path but from root_directory base
        base = Path(root_directory.anchor)
        rel_path = base.joinpath(file_path.relative_to(root_directory))

        bin_obj = Binary(path=rel_path, real_path=file_path)
        is_elf = lief.is_elf(str(file_path))
        if is_elf:
            parser_config = lief.ELF.ParserConfig()
            if bin_obj.name.startswith("libcrypto"):
                parser_config.count_mtd = lief.ELF.ParserConfig.DYNSYM_COUNT.HASH
                logging.debug("lief parser config set to hash for dynsym count")
            parsing_res: lief.ELF.Binary | None = lief.ELF.parse(str(file_path), parser_config)
            if parsing_res is None:
                return f"Lief cannot parse {file_path}"

            # parse imported libs
            for lib in parsing_res.libraries:
                bin_obj.add_imported_library_name(str(lib))

            # parse symbols
            # store name of imported ones and internal functions
            # store exported symbols
            s: lief.ELF.Symbol
            is_kernel_module = bin_obj.path.suffix == ".ko"
            for s in parsing_res.symbols:
                if s.imported:
                    bin_obj.add_imported_symbol_name(str(s.name))
                elif s.exported or is_kernel_module and s.name:
                    is_func = s.is_function or s.type == lief.ELF.Symbol.TYPE.GNU_IFUNC
                    if not is_func and is_kernel_module:
                        continue
                    bin_obj.add_exported_symbol(
                        Symbol(
                            name=str(s.name),
                            is_func=is_func,
                            demangled_name=s.demangled_name,
                            addr=s.value,
                        )
                    )
                elif s.is_function:
                    bin_obj.add_function(
                        Symbol(
                            name=str(s.name),
                            is_func=s.is_function,
                            demangled_name=s.demangled_name,
                            addr=s.value,
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
            res: lief.Binary | None = lief.parse(str(file_path))
            if res is None:
                return f"ERROR: Lief cannot parse {file_path}"
            # parse imported libs
            for lib in res.libraries:
                bin_obj.add_imported_library_name(str(lib))
            for f in res.imported_functions:
                bin_obj.add_imported_symbol_name(str(f.name))
            for f in res.exported_functions:
                bin_obj.add_exported_symbol(
                    Symbol(
                        name=str(f.name),
                        demangled_name=str(f.name),
                        is_func=True,
                        addr=f.address,
                    )
                )

        return (bin_obj, None)

    @classmethod
    def parse_binary_job(cls, ingress: Queue, egress: Queue, root_directory: Path) -> None:
        """Parse an executable file and create the associated Binary object.

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
                    egress.put((path, cls.load_binary(root_directory, path)))
                except Exception as e:
                    egress.put((path, e))
            except queue.Empty:
                pass
            except KeyboardInterrupt:
                break

    def map_binary(self, bin_object: Binary, additional_res: Any = None) -> None:
        """Given a Binary object add it to the DB.

        This function updates the filesystem representation stored as `self.fs`.
        :param bin_object: Binary object
        """
        self.fs.add_binary(bin_object)
        if not self.dry_run_mode:
            self.record_binary_in_db(bin_object, f"[binary mapping] {bin_object.name}")

    def map_symlink(self, path: Path) -> None:
        """Given a symlink, resolve it and create the associated objects if needed.

        If it points on a binary file, add it to the DB and create the associated
        Symlink object. Also add in db a link between the Symlink object and the Binary
        object corresponding to its target.
        This function updates the filesystem representation stored as `self.fs`.
        :param path: Symlink path
        """
        log_prefix = f"[symlinks] '{path.name}'"
        target = path.readlink()
        if not target.is_absolute():
            target = path.resolve()
            if not target.is_relative_to(self.root_directory):
                logging.warning(f"{log_prefix}: points outside of root directory '{target}'")
                return
            if not target.exists() or not self.is_binary_supported(target):
                return None
            target = self.fs.gen_fw_path(target)
        elif (
            target == Path("/dev/null")
            or not target.exists()
            or not self.is_binary_supported(target)
        ):
            return None
        if self.fs.binary_exists(target):
            target_obj = self.fs.get_binary_by_path(target)
            symlink_obj = Symlink(
                path=self.fs.gen_fw_path(path),
                target=target_obj,
            )
            if not self.dry_run_mode:
                if target_obj.id is None:
                    logging.warning(f"{log_prefix}: '{target}' is not a recorded binary")
                    return None
                self.record_symlink_in_db(symlink_obj)
            logging.debug(
                f"{log_prefix}: added symlink {symlink_obj.path} -> \
{symlink_obj.target.path}"
            )
            self.fs.add_symlink(symlink_obj)
        else:
            logging.warning(f"{log_prefix}: '{target}' does not correspond to a recorded binary")

    @dataclass(frozen=True)
    class _LibImport(ABC):
        initial_import: Symlink | Binary | None
        final_import: Binary | None

    class _SolvedLibImport(_LibImport):
        initial_import: Symlink | Binary
        final_import: Binary

        def __init__(self, initial_import: Symlink | Binary, final_import: Binary) -> None:
            super().__init__(initial_import=initial_import, final_import=final_import)

    class _PartialLibImport(_LibImport):
        initial_import: Symlink | Binary

        def __init__(self, initial_import: Symlink | Binary) -> None:
            super().__init__(initial_import=initial_import, final_import=None)

    class _FailedLibImport(_LibImport):
        initial_import = None
        final_import = None

        def __init__(self):
            pass

    class _UndecidedLibImport(_FailedLibImport):
        pass

    def _resolve_lib_import(
        self, lib_name: str, strategy: ResolveDuplicateOption, log_prefix: str
    ) -> _SolvedLibImport | _PartialLibImport | _FailedLibImport | _UndecidedLibImport:
        """Based on its name, find a library.

        Given a library name, it resolve its imports using the following heuristics:
         - look for a binary which have the looked name, if there is a match,
           it is considered as solved, if there is several matches, the mapping will
           depend on the chosen resolution
         - if no binary match, the same heuristics are applied to symlinks. The final
           import will be the target of the symlink (recursively if needed)
        """
        if self.fs.binary_name_exists(lib_name):
            matching_binaries = self.fs.get_binaries_by_name(lib_name)
            lib_obj: Binary | None = self._select_fs_component(
                strategy, matching_binaries, log_prefix, lib_name
            )
            if lib_obj is None:
                return self._FailedLibImport()
            return self._SolvedLibImport(initial_import=lib_obj, final_import=lib_obj)
        elif self.fs.symlink_name_exists(lib_name):
            matching_symlinks = self.fs.get_symlinks_by_name(lib_name)
            sym_obj: Symlink | None = self._select_fs_component(
                strategy, matching_symlinks, log_prefix, lib_name
            )
            if sym_obj is None:
                return self._UndecidedLibImport()
            dest = self.fs.resolve_symlink(sym_obj)
            if dest is None:
                return self._PartialLibImport(initial_import=sym_obj)
            return self._SolvedLibImport(initial_import=sym_obj, final_import=dest)
        else:
            return self._FailedLibImport()

    def map_lib_imports(
        self,
        binary: Binary,
        resolution_strategy: ResolveDuplicateOption = ResolveDuplicateOption.IGNORE,
    ) -> None:
        """Given an already mapped binary, resolve its libraryimports.

        The following heuristics are used:
         - look for a binary which have the looked name, if there is a match,
           it is considered as solved, if there is several matches, the mapping will
           depend on the chosen resolution
         - if no binary match, the same heuristics are applied to symlinks
        This function update the DB with the import links found and each binary's
        'imported libs' field with the corresponding ElfBinary objects (or the
        targeted Binary object in the case of a Symlink)
        """
        log_prefix = f"[lib imports] {binary.path}"
        for lib_name in binary.imported_library_names:
            res = self._resolve_lib_import(lib_name, resolution_strategy, log_prefix)
            match res:
                case self._SolvedLibImport():
                    # For symlinks, we record a ref to the symlink but to ease symbol
                    # resolution, the final target of the symlink is considered to be
                    # imported and not the symlink itself
                    self.record_import_in_db(binary.id, res.initial_import.id, log_prefix)
                    binary.add_imported_library(res.final_import)
                case self._PartialLibImport():
                    self.record_import_in_db(binary.id, res.initial_import.id, log_prefix)
                    logging.warning(
                        f"{log_prefix}: import {res.initial_import.path} symlink which \
does not point on a recorded bin"
                    )
                case self._UndecidedLibImport():
                    logging.warning(
                        f"{log_prefix}: {lib_name} import undecided, not recorded in DB"
                    )
                case self._FailedLibImport():
                    logging.warning(f"{log_prefix}: lib '{lib_name}' not found in FS")
                    if not self.dry_run_mode and self.db_interface is not None:
                        lib_id = self.db_interface.record_class(lib_name, is_indexed=False)
                        self.record_import_in_db(binary.id, lib_id, log_prefix)
                    binary.add_non_resolved_imported_library(lib_name)
                case _:
                    logging.error(
                        f"{log_prefix}: Unknown resolution status for lib {lib_name} \
import, drop case"
                    )

    def _record_non_resolved_symbol_import(self, binary: Binary, symbol_name: str) -> None:
        logging.warning(f"[symbol imports] {binary.name}: cannot resolve {symbol_name}")
        if not self.dry_run_mode and self.db_interface is not None:
            symb_id = self.db_interface.record_field(symbol_name, is_indexed=False)
            self.record_import_in_db(binary.id, symb_id, f"[symbol imports] {binary.name}")
        binary.add_non_resolved_imported_symbol(symbol_name)

    def resolve_symbol_import(
        self,
        binary: Binary,
        func_name: str,
        resolution_strategy: ResolveDuplicateOption,
        log_prefix: str,
    ) -> tuple[Binary, Symbol] | None:
        """Given an already mapped binary and a symbol, resolve this symbol import.

        It is able to treat versionned symbolfs from ELF binaries (e.g. SYMBOL@@GLIBC.1)
        First the version part of the symbol should be resolved, using symbol version
        auxiliary symbols (here GLIBC.1 could be associated to several libs), then we
        could simply solve the symbol import using its name (part before the `@@`) and
        the list of possible libraries it could come from.

        :return: a tuple (imported bin, imported symbol) or None if nothing found
        """
        if len(func_name.split("@@")) == 2:  # symbols with a specific version
            symb_name, symb_version = func_name.split("@@")
            if symb_version in binary.version_requirement:
                for lib_name in binary.version_requirement[symb_version]:
                    res = self._resolve_lib_import(lib_name, resolution_strategy, log_prefix)
                    if isinstance(res, self._SolvedLibImport):
                        lib = res.final_import
                        if lib.exported_symbol_exists(symb_name):
                            return lib, lib.get_exported_symbol(symb_name)
        else:
            for lib in binary.iter_imported_libraries():
                if lib.exported_symbol_exists(func_name):
                    return lib, lib.get_exported_symbol(func_name)
        return None

    def map_symbol_imports(
        self,
        binary: Binary,
        resolution_strategy: ResolveDuplicateOption = ResolveDuplicateOption.IGNORE,
    ) -> None:
        """Given an already mapped binary, resolve its symbols.

        This function update the DB and the current FS with the import links found.
        It is able to treat versionned symbolfs from ELF binaries (e.g. SYMBOL@@GLIBC.1)
        """
        log_prefix = f"[symbol imports] {binary.path}"
        for func_name in binary.imported_symbol_names:
            res = self.resolve_symbol_import(binary, func_name, resolution_strategy, log_prefix)
            if res is None:
                self._record_non_resolved_symbol_import(binary, func_name)
            else:
                callee_bin, callee_symb = res
                if callee_symb.name != func_name:
                    try:
                        binary.remove_imported_symbol(func_name)
                    except KeyError:
                        pass
                binary.add_imported_symbol(callee_symb)
                if not binary.imported_library_exists(callee_bin.name, is_resolved=True):
                    binary.add_imported_library(callee_bin)
                    self.record_import_in_db(binary.id, callee_bin.id)
                self.record_import_in_db(binary.id, callee_symb.id)

    # ================================ Main functions ==================================

    @staticmethod
    def _is_list_str(x: list) -> bool:
        """:return: True if isinstance(x, list[str])"""
        return isinstance(x, list) and all(map(lambda i: isinstance(i, str), x))

    def _correct_map_result(self, res: Any) -> bool:
        """:return: True if res is a tuple[Binary, Any]"""
        return isinstance(res, tuple) and len(res) == 2 and isinstance(res[0], Binary)

    def _treat_bin_parsing_result(self, path: Path, res: Any):
        """Handle load_binary res, map it or display error."""
        log_prefix = f"[binary mapping] {path.name}"
        if isinstance(res, str):
            logging.error(f"{log_prefix}: {res}")
        elif self._correct_map_result(res):
            bin_obj, additional_info = res
            self.map_binary(bin_obj, additional_info)
        else:
            logging.warning(f"{log_prefix}: impossible to parse the following result {res}")

    def map_binaries_main(self, threads: int, progress: Progress) -> None:
        """Parse and map binaries of a given directory.

        Record them in self.fs and self.db (except if self.is_dry_run == True).
        :param threads: number of threads to use
        :param progress: a rich.progress bar object for cli rendering
        """
        binary_paths = set(
            filter(lambda p: self.is_binary_supported(p), self.root_directory.rglob("*"))
        )

        logging.debug(f"[main] Start Binaries parsing: {len(binary_paths)} binaries to parse")
        binaries_map = progress.add_task("[deep_pink2]Binaries mapping", total=len(binary_paths))
        if threads > 1:  # multiprocessed case
            ctx = get_context("spawn")  # fork usage deprecated starting 3.12
            manager = ctx.Manager()
            ingress = manager.Queue()
            egress = manager.Queue()
            pool = ctx.Pool(threads)

            # Launch all workers and fill input queue
            for _ in range(threads - 1):
                pool.apply_async(self.parse_binary_job, (ingress, egress, self.root_directory))
            for path in binary_paths:
                ingress.put(path)
            logging.debug(f"[main] {threads - 1} threads created")

            i = 0
            while True:
                path, res = egress.get()
                i += 1
                self._treat_bin_parsing_result(path, res)
                progress.update(binaries_map, advance=1)
                if i == len(binary_paths):
                    break
            pool.terminate()
        else:
            logging.debug("[main] One thread mode")
            for path in binary_paths:
                res = self.load_binary(self.root_directory, path)
                self._treat_bin_parsing_result(path, res)
                progress.update(binaries_map, advance=1)
        self.commit()

    def map_symlinks_main(self, progress: Progress):
        """Parse and resolve symlinks. Record them in self.fs and self.db.

        :param progress: a rich.progress bar object for cli rendering
        """
        symlink_paths = set(filter(lambda p: p.is_symlink(), self.root_directory.rglob("*")))
        logging.debug(f"[main] Start Symlinks parsing: {len(symlink_paths)} symlinks to parse")
        symlinks_map = progress.add_task("[deep_pink2]Symlinks mapping", total=len(symlink_paths))
        for path in symlink_paths:
            self.map_symlink(path)
            progress.update(symlinks_map, advance=1)
        self.commit()

    def map_lib_imports_main(
        self, progress: Progress, resolution_strategy: ResolveDuplicateOption
    ) -> None:
        """Resolve all the lib imports.

        Record them in self.fs and self.db (except if self.is_dry_run == True).
        :param progress: a rich.progress bar object for cli rendering
        :param resolution_strategy: the chosen option for duplicate import resolution
        """
        logging.debug("[main] Start Libraries imports resolution")
        lib_imports = progress.add_task(
            "[orange_red1]Library imports mapping", total=len(list(self.fs.iter_binaries()))
        )
        for binary in self.fs.iter_binaries():
            self.map_lib_imports(binary, resolution_strategy)
            progress.update(lib_imports, advance=1)
        self.commit()

    def map_symbol_imports_main(
        self, progress: Progress, resolution_strategy: ResolveDuplicateOption
    ) -> None:
        """Resolve all the symbols imports.

        Record them in self.fs and self.db (except if self.is_dry_run == True).
        :param progress: a rich.progress bar object for cli rendering
        :param resolution_strategy: the chosen option for duplicate import resolution
        """
        logging.debug("[main] Start Symbols imports resolution")
        symbol_imports = progress.add_task(
            "[orange1]Symbol imports mapping", total=len(list(self.fs.iter_binaries()))
        )
        for binary in self.fs.iter_binaries():
            self.map_symbol_imports(binary, resolution_strategy)
            progress.update(symbol_imports, advance=1)
        self.commit()

    def mapper_main(
        self,
        threads: int,
        progress: Progress,
        resolution_strategy: ResolveDuplicateOption = ResolveDuplicateOption.IGNORE,
    ) -> FileSystem:
        """Map recursively the content of a given directory.

        Main mapper function, map the content of 'self.root_directory', in the order:
        - binaries;
        - symlinks (and resolve them);
        - lib imports;
        - symbol imports.
        It updates the fields and the DB
        :param threads: number of threads to use
        :param progress: a rich.progress bar object for cli rendering
        :param resolution_strategy: the chosen option for duplicate import resolution
        :return: The FileSystem object filled
        """
        self.map_binaries_main(threads, progress)

        # Parse and resolve symlinks
        self.map_symlinks_main(progress)

        # Handle imports
        self.map_lib_imports_main(progress, resolution_strategy)
        self.map_symbol_imports_main(progress, resolution_strategy)
        # Return the internal object. The caller can do whathever
        # we wants with it, like saving it to a file etc.
        return self.fs
