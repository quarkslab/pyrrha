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
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from multiprocessing import Queue, get_context
from pathlib import Path
from typing import Any, overload

from numbat import SourcetrailDB
from numbat.exceptions import DBException
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

from pyrrha_mapper.exceptions import PyrrhaError
from pyrrha_mapper.types import ResolveDuplicateOption

from .objects import Binary, FileSystem, Symbol, Symlink


@contextmanager
def hide_progress(progress: Progress):
    """Context Manager which temporally hide a `rich` progress bar.

    Code from https://github.com/Textualize/rich/issues/1535#issuecomment-1745297594
    """
    transient = progress.live.transient  # save the old value
    progress.live.transient = True
    progress.stop()
    progress.live.transient = transient  # restore the old value
    try:
        yield
    finally:
        # make space for the progress to use so it doesn't overwrite any previous lines
        print("\n" * (len(progress.tasks) - 2))
        progress.start()


class FileSystemImportsMapper:
    """Filesystem mapper based on Lief, which computes imports and exports.

    It maps a filesystem in the following order:
    - binaries
    - symlinks
    - lib imports
    - symbol_imports.
    To change the behavior of these mapping you can reimplement the
    map_* corresponding method.

    Init params
    :param root_directory: directory containing the filesystem to map
    :param db: interface to the DB
    """

    def __init__(self, root_directory: Path | str, db: SourcetrailDB | None):
        import lief

        lief.logging.disable()

        self.root_directory = Path(root_directory).resolve().absolute()
        self.db_interface = db
        self.fs = FileSystem(root_dir=self.root_directory)
        self._dry_run = not bool(db)

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
        import lief

        lief.logging.disable()

        return p.is_file() and not p.is_symlink() and (lief.is_elf(str(p)) or lief.is_pe(str(p)))

    @property
    def dry_run_mode(self) -> bool:
        """Returns whether a Sourcetrail DB as been provided or not.

        If not, only produce the FileSystem object that can also
        be used independently.
        """
        return self._dry_run

    @dry_run_mode.setter
    def dry_run_mode(self, value: bool) -> None:
        """If True does not record in db."""
        self._dry_run = value

    # ===================== Records in DB (NumbatUI DB) ===============================

    def record_import_in_db(
        self, source_id: int | None, dest_id: int | None, log_prefix: str = ""
    ) -> None:
        """Record in DB the import of dest by source."""
        if self.dry_run_mode:
            return None
        assert self.db_interface is not None
        if source_id is None or dest_id is None:
            logging.error(f"{log_prefix}: Cannot record import, src and/or dest are unknown")
        else:
            self.db_interface.record_ref_import(source_id, dest_id)

    def record_binary_in_db(self, binary: Binary, log_prefix: str = "") -> Binary:
        """Record the binary inside the DB as well as its internal symbols.

        Update 'bin_obj.id' with the id of the created object in DB and does the same
        thing for its symbol. It will record symbols using their demangled names.

        :warning: do not record calls as well as any links between several binaries

        :param binary: the Binary object to map
        :return: the updated object
        """
        # If dry run do not store the binary in DB
        if self.dry_run_mode:
            return binary

        assert self.db_interface is not None
        binary.id = self.db_interface.record_class(
            binary.name, prefix=f"{binary.path.parent}/", delimiter=":"
        )
        if binary.id is None:
            logging.error(f"{log_prefix}: Record of binary failed.")
            return binary

        recorded_symb: dict[str, int] = dict()
        for symbol in set(binary.iter_exported_symbols()):
            if symbol.demangled_name in recorded_symb:
                logging.debug(
                    f"{log_prefix}: demangled name {symbol.demangled_name} already in db "
                    "common node for these symbols"
                )
                symbol.id = recorded_symb[symbol.demangled_name]
                # Also propagate the id to any other symbol registered under
                # the same mangled name (e.g. secondary demangled-key entries).
                for other in binary.exported_functions.values():
                    if other.name == symbol.name and other.id is None:
                        other.id = symbol.id
                continue
            if symbol.is_func:
                symbol.id = self.db_interface.record_method(
                    symbol.demangled_name,
                    parent_id=binary.id,
                    prefix=hex(symbol.addr) if symbol.addr is not None else "None",
                )
                if symbol.id is not None:
                    self.db_interface.change_node_color(
                        symbol.id, fill_color="#bee0af", border_color="#395f33"
                    )
            else:
                symbol.id = self.db_interface.record_field(
                    symbol.demangled_name,
                    parent_id=binary.id,
                    prefix=hex(symbol.addr) if symbol.addr is not None else "None",
                )

            if symbol.id is None:
                logging.error(f"{log_prefix}: Record of symbol '{symbol.demangled_name}' failed.")
            else:
                try:
                    self.db_interface.record_public_access(symbol.id)
                    recorded_symb[symbol.demangled_name] = symbol.id
                    # Propagate id to all symbols sharing the same mangled name
                    # (covers secondary demangled-key registrations).
                    for other in binary.exported_functions.values():
                        if other.name == symbol.name and other.id is None:
                            other.id = symbol.id
                except DBException as e:
                    raise PyrrhaError(
                        f"{log_prefix}: Cannot register access to symbol {symbol.demangled_name}: "
                        f"{e}"
                    ) from e

        for symbol in set(binary.iter_not_exported_functions()):
            # Skip if this demangled name was already recorded as an exported
            # symbol — same demangled name means same DB node, and calling
            # record_private_access on it would violate the UNIQUE constraint.
            if symbol.demangled_name in recorded_symb:
                logging.debug(
                    f"{log_prefix}: demangled name {symbol.demangled_name} already recorded "
                    "as exported, skipping internal registration"
                )
                symbol.id = recorded_symb[symbol.demangled_name]
                continue
            symbol.id = self.db_interface.record_method(
                symbol.demangled_name,
                parent_id=binary.id,
                prefix=hex(symbol.addr) if symbol.addr is not None else "None",
            )
            if symbol.id is None:
                logging.error(f"{log_prefix}: Record of symbol '{symbol.demangled_name}' failed.")
            else:
                try:
                    self.db_interface.record_private_access(symbol.id)
                    recorded_symb[symbol.demangled_name] = symbol.id
                except DBException as e:
                    raise PyrrhaError(
                        f"{log_prefix}: Cannot register access to symbol"
                        f" {symbol.demangled_name}: {e}"
                    ) from e

        return binary

    def record_symlink_in_db(self, sym: Symlink, log_prefix: str = "") -> Symlink:
        """Record into DB the symlink and its link to its target.

        Update 'sym.id' with the id of the created object.
        :param sym: symlink object
        :return: the updated object
        """
        if self.dry_run_mode:
            return sym
        assert self.db_interface is not None
        sym.id = self.db_interface.record_typedef_node(
            sym.name, prefix=f"{sym.path.parent}/", delimiter=":"
        )
        if sym.id is None:
            logging.error(f"{log_prefix}: Record of symlink failed.")
        else:
            self.record_import_in_db(sym.id, sym.target.id)
        return sym

    # =============================== Utils ===============================

    @overload
    @staticmethod
    def _select_fs_component(
        strategy: ResolveDuplicateOption,
        matching_objects: list[Binary],
        log_prefix: str,
        target_name: str,
        cache: set[Binary] | None = None,
    ) -> Binary | None: ...

    @overload
    @staticmethod
    def _select_fs_component(
        strategy: ResolveDuplicateOption,
        matching_objects: list[Symlink],
        log_prefix: str,
        target_name: str,
        cache: set[Symlink] | None = None,
    ) -> Symlink | None: ...

    @staticmethod
    def _select_fs_component(
        strategy: ResolveDuplicateOption,
        matching_objects: list[Binary] | list[Symlink],
        log_prefix: str,
        target_name: str,
        cache: set[Binary] | set[Symlink] | None = None,
    ) -> Binary | Symlink | None:
        """Choice of one element of a given list according to the strategy.

        Given a list of objects which match a target, select one or None among
        the given list according the strategy given It also logs the choice made
        (debug level). If requireds by the strategy, an interaction with the user could
        be made.
        :param strategy: the resolution strategy
        :param matching_objects: a list of FileSystemComponents (NOT empty, not
           check by the function)
        :param log_prefix: Prefix used at the beginning of each log
        :param target_name: Target name, used in logs (and user interaction)
        :param resolve_cache: cache of previously selected choices for this target
        :return: the selected FileSystemComponent | None if resolution strategy
           is IGNORE
        """
        if len(matching_objects) > 1 and strategy is ResolveDuplicateOption.IGNORE:
            logging.debug(
                f"{log_prefix}: several matches for {target_name} but strategy is "
                f"{ResolveDuplicateOption.IGNORE.name} so nothing selected"
            )
            return None
        selected_index = None
        selected_bin = None
        if len(matching_objects) > 1 and strategy is ResolveDuplicateOption.INTERACTIVE:
            for cache_entry in cache or {}:
                if cache_entry in matching_objects:  # reuse already selected entry
                    logging.debug(
                        f"{log_prefix}: manually selected entry to disambiguate {target_name}"
                    )
                    selected_bin = cache_entry

            while (
                selected_bin is None
                or selected_index is None
                or selected_index < 0
                or selected_index >= len(matching_objects)
            ):
                print(f"{log_prefix}: several matches for {target_name}, select one\n")
                for i in range(len(matching_objects)):
                    print(f"{i}: {matching_objects[i].path}")
                try:
                    selected_index = int(input())
                except ValueError:
                    print("Enter a valid number")
        else:  # "arbitrary" option
            selected_index = 0
        if selected_bin is None:
            selected_bin = matching_objects[selected_index]
        return selected_bin

    def commit(self) -> None:
        """Commit changes in database."""
        if not self.dry_run_mode and self.db_interface is not None:
            self.db_interface.commit()

    # ===================  Binary parsing ==============================

    def load_binary_args(self) -> dict[str, Any]:
        """Return dict of args for load_binary that are always the same for the wholde firmware.

        Use to optimize multiprocessing. Set here there real values.
        """
        return {"root_directory": self.root_directory}

    @staticmethod
    def load_binary(root_directory: Path, file_path: Path) -> tuple[Binary, Any] | str:
        """Create a Binary object from a given file using lief.

        raise: FsMapperError if cannot load it
        :return: bin object and additionnal info if needed or a string in case of error
        """
        import lief

        lief.logging.disable()
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

            bin_obj.image_base = parsing_res.imagebase
            bin_obj.is_relocatable = parsing_res.header.file_type == lief.ELF.Header.FILE_TYPE.REL
            # Extract the ELF SONAME if present (shared libraries only).
            # This allows resolving imports that reference the SONAME rather
            # than the actual filename (e.g. libpthread.so.0 vs libpthread-2.11.1.so).
            for dyn_entry in parsing_res.dynamic_entries:
                if dyn_entry.tag == lief.ELF.DynamicEntry.TAG.SONAME:
                    bin_obj.soname = str(dyn_entry.name)
                    break
            # parse imported libs
            for lib in parsing_res.libraries:
                bin_obj.add_imported_library_name(str(lib))

            # parse symbols
            # store name of imported ones and internal functions
            # store exported symbols
            s: lief.ELF.Symbol
            is_kernel_module = bin_obj.path.suffix == ".ko"
            seen_symbol_names: set[str] = set()
            for s in parsing_res.symbols:
                sym_name = str(s.name)
                if s.imported:
                    bin_obj.add_imported_symbol_name(sym_name)
                elif s.exported or is_kernel_module and s.name:
                    is_func = s.is_function or s.type == lief.ELF.Symbol.TYPE.GNU_IFUNC
                    if not is_func and is_kernel_module:
                        continue
                    # LIEF may yield the same symbol name from both .symtab
                    # and .dynsym; only register the first occurrence to avoid
                    # duplicate DB entries (UNIQUE constraint on node_id).
                    if sym_name in seen_symbol_names:
                        continue
                    seen_symbol_names.add(sym_name)
                    # Use the mangled name as demangled_name when LIEF's
                    # demangled_name is identical to the mangled name (i.e.
                    # demangling was not available or not needed).
                    lief_demangled = str(s.demangled_name)
                    demangled = lief_demangled if lief_demangled != sym_name else sym_name
                    sym = Symbol(
                        name=sym_name,
                        is_func=is_func,
                        demangled_name=demangled,
                        addr=s.value,
                    )
                    # Register under the mangled name as primary key.
                    # Also register under the demangled name if it differs,
                    # so that call-graph resolution can match short callee
                    # strings against exported_functions keys.
                    bin_obj.add_exported_symbol(sym)
                    if demangled != sym_name:
                        bin_obj.add_exported_symbol(sym, symbol_name=demangled)
                elif s.is_function:
                    # Skip symbols already registered as exported functions to
                    # avoid duplicate DB entries.
                    if sym_name in seen_symbol_names:
                        continue
                    seen_symbol_names.add(sym_name)
                    bin_obj.add_function(
                        Symbol(
                            name=sym_name,
                            is_func=s.is_function,
                            demangled_name=str(s.demangled_name),
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
            bin_obj.image_base = res.imagebase
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
    def parse_binary_job(cls, ingress: Queue, egress: Queue, parse_func: Callable) -> None:
        """Parse an executable file and create the associated Binary object, used to multiprocess.

        :param ingress: input Queue, contains Path items or None as a stop sentinel
        :param egress: output Queue, sends back (file path, Binary result) or
            (file path, Exception) if an issue occurred
        :param parse_func: func which takes a path as argument (called file_path) and parses it
        """
        while True:
            try:
                path = ingress.get(timeout=0.5)
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                break

            if path is None:
                break

            try:
                egress.put((path, parse_func(file_path=path)))
            except Exception as e:
                logging.error(f"[worker] Failed on {path}: {e}")
                egress.put((path, e))

    def map_binary(self, bin_object: Binary, additional_res: Any = None) -> None:
        """Given a Binary object add it to the DB.

        This function updates the filesystem representation stored as `self.fs`.
        :param bin_object: Binary object
        """
        self.fs.add_binary(bin_object)
        if not self.dry_run_mode:
            self.record_binary_in_db(bin_object, f"[binary mapping] {bin_object.name}")

    # =============================== Symlinks ==================================

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

    # =============================== Imports ==================================

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
        elif self.fs.soname_exists(lib_name):
            # The imported name matches the SONAME of a binary whose filename
            # differs (e.g. libpthread.so.0 is the SONAME of libpthread-2.11.1.so).
            matching_binaries = self.fs.get_binaries_by_soname(lib_name)
            lib_obj = self._select_fs_component(strategy, matching_binaries, log_prefix, lib_name)
            if lib_obj is None:
                return self._FailedLibImport()
            return self._SolvedLibImport(initial_import=lib_obj, final_import=lib_obj)
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

                    if lib_name != res.final_import.name:
                        # SONAME case: store the resolved binary under the
                        # original import name (the SONAME) rather than the
                        # binary's filename, to avoid a spurious extra entry.
                        binary.imported_libraries[lib_name] = res.final_import
                    else:
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
        load_bin_func = partial(self.load_binary, **self.load_binary_args())
        if threads > 1:  # multiprocessed case
            ctx = get_context("spawn")  # fork usage deprecated starting 3.12
            manager = ctx.Manager()
            ingress = manager.Queue()
            egress = manager.Queue()
            pool = ctx.Pool(threads)
            parse_job = partial(self.parse_binary_job, parse_func=load_bin_func)

            # Launch all workers and fill input queue
            for _ in range(threads - 1):
                pool.apply_async(parse_job, (ingress, egress))
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
                res = load_bin_func(file_path=path)
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

    def map(
        self,
        threads: int,
        resolution_strategy: ResolveDuplicateOption = ResolveDuplicateOption.IGNORE,
    ) -> FileSystem:
        """Wrap mapper_main with usefull elements for CLI rendering.

        :param threads: number of threads to use
        :param resolution_strategy: the chosen option for duplicate import resolution
        :return: The FileSystem object filled
        """
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        ) as progress:
            return self.mapper_main(threads, progress, resolution_strategy)

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
