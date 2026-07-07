# -*- coding: utf-8 -*-

#  Copyright 2023-2026 Quarkslab
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
"""Decompilation code binary mapper."""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import NamedTuple

from numbat import SourcetrailDB
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

from pyrrha_mapper.backend import IDA, Backend, Ghidra
from pyrrha_mapper.types import FuncType

from .decomp_objects import ExportedDecompilation
from .objects import Binary, Symbol


class Location(NamedTuple):
    """Location inside a text of a word or more."""

    start_line: int
    start_col: int
    end_line: int
    end_col: int


@dataclass
class FuncData:
    """Store function data collected by the binary parser.

    All addresses are in **parser space** (the native address space of the
    underlying tool — IDA, Ghidra, etc.).
    """

    symbol: Symbol
    type: FuncType
    calls: list[int]
    callers: list[int]
    source: str
    source_id: int | None = None
    declaration: Location | None = None
    # Keyed by callee (parser-space) address; defaultdict so call-site locations
    # can be appended without pre-seeding each callee entry.
    source_calls_loc: dict[int, list[Location]] = field(default_factory=lambda: defaultdict(list))

    @property
    def id(self) -> int | None:
        """:return: the associated DB id if any"""
        return self.symbol.id

    @id.setter
    def id(self, val: int) -> None:
        self.symbol.id = val

    @property
    def name(self) -> str:
        """:return: mangled name of the function"""
        return self.symbol.name

    @property
    def demangled_name(self) -> str:
        """:return: demangled name of the function"""
        return self.symbol.demangled_name

    @property
    def addr(self) -> int:
        """:return: address of the function in the Binary"""
        assert self.symbol.addr is not None
        return self.symbol.addr


def normalize_name(name: str) -> str:
    """Transform function name."""
    return name.strip("_").strip(".")


class DecompilMapper(Backend):
    """Map a single binary's decompiled source and call graph into a Sourcetrail DB."""

    def __init__(
        self,
        db: SourcetrailDB,
        bin_path: Path,
    ) -> None:
        self.db_interface = db
        super().__init__(bin_path, None, decompilation=True)
        self.bin = Binary(path=bin_path)
        self.functions: dict[int, FuncData] = dict()
        self.source_ids: dict[int, int] = dict()
        self.db_interface.set_node_type("file", "Sources", "source")

    def record_function(self, func: FuncData, log_prefix) -> FuncData:
        """Record a function into the DB (do not record the associated source).

        :return: updated func data with id
        """
        if func.type == FuncType.IMPORTED:
            logging.debug(f"{log_prefix}: extern function, skip")
            return func  # do not add EXTERN functions
        f_id = self.db_interface.record_function(
            func.demangled_name,
            prefix=hex(func.addr) if func.addr is not None else "None",
        )
        if f_id is None:
            logging.error(f"{log_prefix}: error while recording function in db")
        else:
            func.id = f_id
        return func

    def index_function(self, addr: int, log_prefix: str) -> None:
        """Iterate over all the functions of the binary and extract useful data.

        Record function at the given address (addr) into DB and as member of
        self.binary.
        """
        func_type = self.func_type(addr)
        func_data = FuncData(
            symbol=Symbol(
                name=self.func_mangled_name(addr),
                demangled_name=self.func_demangled_name(addr),
                is_func=True,
                addr=addr,
            ),
            type=func_type,
            calls=self.func_children(addr),
            callers=self.func_parents(addr),
            source=self.func_decompiled(addr) if func_type != FuncType.IMPORTED else "",
        )
        self.bin.add_function(func_data.symbol)
        self.functions[addr] = self.record_function(func_data, log_prefix)

    def record_source(self, func: FuncData, log_prefix: str) -> FuncData:
        """Record decompiled version of each function.

        :param func: Func data object to  treat
        :param log_prefix: string prepended to every log message.
        :return: updated func data object
        """
        # Write the source to a temporary file, hand its path to the DB, then
        # remove it. delete=False (rather than NamedTemporaryFile auto-delete)
        # is required because record_file reopens the path: on Windows an open
        # NamedTemporaryFile cannot be reopened, and delete_on_close only
        # exists on Python >= 3.12 while the project supports 3.11.
        tmp = NamedTemporaryFile(mode="wt", delete=False)
        try:
            tmp.write(func.source)
            tmp.close()
            # The file is recorded under a name that includes the function
            # address: numbat derives the file node from this name, and two
            # functions can share a mangled name (e.g. tool-generated or
            # versioned symbols). A non-unique name reuses the existing file
            # node id and then re-inserts a file row with it, raising a UNIQUE
            # constraint error on file.id.
            file_name = f"{func.name}@{func.addr:#x}"
            func.source_id = self.db_interface.record_file(Path(tmp.name), name=file_name)
            if func.source_id is None:
                return func
            self.db_interface.record_file_language(func.source_id, "cpp")

            logging.debug(f"{log_prefix}: add function {func.name} to file {func.source_id}")
            if func.id is not None and func.declaration is not None:
                self.db_interface.record_symbol_location(func.id, func.source_id, *func.declaration)
            else:
                logging.warning(f"{log_prefix}: declaration not found in source code")
        finally:
            Path(tmp.name).unlink(missing_ok=True)

        return func

    def index_decompiled(self, addr, log_prefix) -> None:
        """Locate the declaration and every call-site inside the source of function at address addr.

        Record the associated source.
        :param addr: address of the function to treat
        :param log_prefix: string prepended to every log message.
        """
        func = self.functions[addr]

        # Imported functions have no decompiled body (source is set to "" in
        # index_function), so there is nothing to locate or record. Skip them
        # to avoid spurious "declaration not found" errors.
        if func.type == FuncType.IMPORTED:
            return

        # Build lookup tables for the callees of this function.
        # normalize_name strips leading/trailing underscores and dots so that
        # e.g. "__memcpy" and "memcpy" both match the same call-site token.
        callee_name_to_addr: dict[str, int] = {
            normalize_name(self.functions[callee_addr].name): callee_addr
            for callee_addr in func.calls
            if callee_addr in self.functions and self.functions[callee_addr].name
        }

        func_name = normalize_name(func.name)

        for line_index, line_text in enumerate(func.source.splitlines()):
            # Lines in Location are 1-based; line_index is 0-based.
            line_number = line_index + 1

            # Try to find the function declaration on this line.
            if func.declaration is None:
                decl_col = line_text.find(func_name)
                if decl_col != -1:
                    func.declaration = Location(
                        line_number,
                        decl_col + 1,
                        line_number,
                        decl_col + len(func_name),
                    )

            # Scan the line for each callee name, recording the start column of
            # every hit.  The dict key is the column so overlaps are detected
            # in the sort pass below.
            # key: start_col, value: (callee_addr, callee_name)
            hits_by_col: dict[int, tuple[int, str]] = {}

            for callee_name, callee_addr in callee_name_to_addr.items():
                # If the stored name includes a type signature (e.g. "func(int)")
                # strip to the bare identifier before searching.
                search_token = (
                    callee_name.split("(")[0] if callee_name.endswith(")") else callee_name
                )
                hit_col = line_text.find(f"{search_token}(")
                if hit_col != -1:
                    hits_by_col[hit_col] = (callee_addr, callee_name)

            # Process hits left-to-right so that a longer earlier match
            # (e.g. "lxstat") shadows a shorter later substring (e.g. "xstat").
            # end_of_last_accepted tracks the column just past the last accepted
            # match so that substring overlaps are detected.
            end_of_last_accepted = 0
            last_accepted_col = 0
            last_accepted_name = ""

            for start_col, (callee_addr, callee_name) in sorted(hits_by_col.items()):
                if start_col < end_of_last_accepted:
                    # This hit starts inside the span of the previous match.
                    if start_col + len(
                        callee_name
                    ) == end_of_last_accepted and last_accepted_name.endswith(callee_name):
                        # The hit is a suffix of the accepted match — expected,
                        # not a real overlap (e.g. "stat" at the end of "lxstat").
                        logging.debug(
                            f"{log_prefix}: skip '{callee_name}' — suffix of '{last_accepted_name}'"
                        )
                    else:
                        logging.warning(
                            f"{log_prefix}: skip '{callee_name}' [col {start_col}] — "
                            f"overlaps '{last_accepted_name}' [col {last_accepted_col}]"
                        )
                else:
                    func.source_calls_loc[callee_addr].append(
                        Location(
                            line_number,
                            start_col + 1,
                            line_number,
                            start_col + len(callee_name),
                        )
                    )
                    end_of_last_accepted = start_col + len(callee_name)
                    last_accepted_col = start_col
                    last_accepted_name = callee_name

        if func.declaration is None:
            logging.error(f"{log_prefix}: function declaration not found in source code")

        self.functions[addr] = self.record_source(func, log_prefix)

    def index_call_graph(self, addr, log_prefix) -> None:
        """Map the call graph of the function at address addr.

        It also map as the associated references in source if any.
        Record the callgraph into db..
        :param addr: address of the function to treat
        :param log_prefix: string prepended to every log message.
        """
        func = self.functions[addr]
        # Imported functions have no body and are not recorded in the DB, so
        # they cannot be callers; skip them without warning.
        if func.type == FuncType.IMPORTED:
            return
        if func.id is None:
            logging.warning(f"{log_prefix}: {func.name}  is not a registered function, skip")
            return
        for child_addr in func.calls:
            if child_addr not in self.functions:
                logging.warning(
                    f"{log_prefix}: Calls to {child_addr:0x} addr from {func.name} "
                    + "does not match a registered function"
                )
                continue
            child = self.functions[child_addr]
            if child.id is None:
                # Imported callees are never recorded in the DB (they have no
                # body), so a missing id is expected rather than an error.
                level = logging.DEBUG if child.type == FuncType.IMPORTED else logging.WARNING
                logging.log(
                    level,
                    f"{log_prefix}: cannot record call to {child.name} from {func.name} "
                    + "missing target id.",
                )
                continue
            ref_id = self.db_interface.record_ref_call(func.id, child.id)

            # source_calls_loc is keyed by the *callee* address (see
            # index_decompiled), so look up the locations for this child.
            child_locations = func.source_calls_loc.get(child_addr, [])
            if (
                ref_id is None
                or func.source == ""
                or child_locations == []
                or func.source_id is None
            ):
                continue
            for location in child_locations:
                self.db_interface.record_reference_location(ref_id, func.source_id, *location)

    def map(self) -> bool:
        """Run the successive steps of the mapping.

        :return: True if the binary node was recorded and indexing ran, else False.
        """
        # Record the binary as a class node so functions can be attached to it
        # via parent_id. Without this id, record_function would orphan every
        # function. Mirrors InterImageCGMapper.record_binary_in_db.

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        ) as progress:
            func_addrs = list(self.func_addrs)
            func_indexing = progress.add_task("[red]Function indexing", total=len(func_addrs))
            for addr in func_addrs:
                self.index_function(addr, f"[function indexing] {addr:#x}")
                progress.update(func_indexing, advance=1)

            decompilee_indexing = progress.add_task(
                "[orange_red1]Source indexing", total=len(self.functions)
            )
            for addr in self.functions.keys():
                self.index_decompiled(addr, f"[source indexing] {self.functions[addr].name}")
                progress.update(decompilee_indexing, advance=1)

            cg_indexing = progress.add_task("[gold1]Call graph indexing", total=len(self.functions))
            for addr in self.functions.keys():
                self.index_call_graph(addr, f"[call graph indexing] {self.functions[addr].name}")
                progress.update(cg_indexing, advance=1)

        self.close()
        return True

    def to_export(self) -> ExportedDecompilation:
        """Build a serialisable export of the current mapping result.

        :return: an ExportedDecompilation projecting this mapper's binary and
            functions into a JSON-serialisable model.
        """
        return ExportedDecompilation.from_mapper(self)


class IdaDecompilMapper(DecompilMapper, IDA):
    """Decompile Mapper backed by IDA Pro."""

    pass


class GhidraDecompilMapper(DecompilMapper, Ghidra):
    """Decompile Mapper backed by Ghidra."""

    pass
