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
"""Base classes for mapping binaries of a filesystem."""

import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import overload

from numbat import SourcetrailDB
from numbat.exceptions import DBException
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

from pyrrha_mapper.common.objects import Binary, FileSystem, Symlink
from pyrrha_mapper.exceptions import PyrrhaError
from pyrrha_mapper.types import ResolveDuplicateOption


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


class FileSystemMapper(ABC):
    """Abstract class which is a base mapper to binaries of a filesystem.

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
        self.root_directory = Path(root_directory).resolve().absolute()
        self.db_interface = db
        self.fs = FileSystem(root_dir=self.root_directory)
        self._dry_run = not bool(db)

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
        # dict demangled_name -> id to check if a demangled name has already been recorded
        recorded_symb: dict[str, int] = dict()
        for symbol in set(binary.iter_exported_symbols()):
            if symbol.demangled_name in recorded_symb:
                logging.debug(
                    f"{log_prefix}: demangled name {symbol.demangled_name} already in db "
                    "common node for these symbols"
                )
                symbol.id = recorded_symb[symbol.demangled_name]
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
                except DBException as e:
                    raise PyrrhaError(
                        f"{log_prefix}: Cannot register access to symbol {symbol.demangled_name}: "
                        f"{e}"
                    ) from e
        for symbol in set(binary.iter_not_exported_functions()):
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

    # ================================ Main function ==================================

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

    @abstractmethod
    def mapper_main(
        self,
        threads: int,
        progress: Progress,
        resolution_strategy: ResolveDuplicateOption = ResolveDuplicateOption.IGNORE,
    ) -> FileSystem:
        """Main function of the mapper, return the result stored in a FileSytsem.

        :param threads: number of threads to use
        :param progress: a progress bar ready to be filled
        :param resolution_strategy: the chosen option for duplicate import resolution
        :return: The FileSystem object filled
        """  # noqa: D401
        pass
