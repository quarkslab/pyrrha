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
"""Load information used by InterCGMapper from the files on the disk."""

import logging
import re
from abc import abstractmethod
from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path
from typing import NamedTuple

from pyrrha_mapper.common import Binary, Symbol
from pyrrha_mapper.exceptions import FsMapperError
from pyrrha_mapper.fs import FileSystemImportsMapper


class FuncType(StrEnum):
    """Represent the type of a function."""

    IMPORTED = "imported"
    LIBRARY = "library"
    NORMAL = "normal"
    THUNK = "thunk"


class FuncData(NamedTuple):
    """Store function data collected by the binary parser.

    All addresses are in **parser space** (the native address space of the
    underlying tool — IDA, Ghidra, etc.).
    """

    symbol: Symbol
    type: FuncType
    calls: list[int]
    callers: list[int]

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


def _count_leading_underscores(name: str) -> int:
    """:return: the number of leading underscores/dots in name"""
    return len(name) - len(name.lstrip("_."))


# Tool-generated fallback names (FUN_<HEX>, sub_<HEX>, _INIT_<N>, _FINI_<N>).
# A trampoline destination that matches one of these cannot be resolved as a
# cross-binary callee — skip the substitution to preserve the original name.
_SYNTHETIC_FUNC_NAME_RE: re.Pattern[str] = re.compile(
    r"^(?:FUN_[0-9A-Fa-f]+|sub_[0-9A-Fa-f]+|_INIT_\d+|_FINI_\d+)$"
)


class BinaryParser:
    """Abstract base class that parses a binary and extracts call-graph data.

    Subclasses implement the parser-specific methods (IDA, Ghidra, …).
    Adresses are the one used in the backend, which can differ from LIEF ones
    (relative vs virtual).
    """

    def __init__(self, root_directory: Path, file_path: Path) -> None:
        self.log_prefix = f"[binary parsing] {file_path.name}"
        self._is_relocatable: bool = False
        self._binary = self._generate_lief_bin(root_directory, file_path)
        self._is_relocatable = self._binary.is_relocatable
        self._initiate_bin_parser(root_directory, file_path, self._binary.image_base)

        image_base = self._binary.image_base

        # Remap LIEF export addresses to parser space.
        parser_exports: dict[int, list[Symbol]] = {
            lief_addr - image_base: symbols
            for lief_addr, symbols in self._binary.exported_funcs_by_addr.items()
        }

        # Step 1 — merge parser functions with LIEF export metadata.
        program_data: dict[int, FuncData] = self._combine_program_analysis_binary(parser_exports)

        # Step 2 — add exported symbols not discovered by the parser.
        # Skipped for ET_REL: LIEF addresses are section-relative and incompatible
        # with the parser address space; Step 1 already matched exports by name.
        parser_addrs: set[int] = set(self._iter_func_addr())
        call_graph: dict[Symbol, list[str]] = {}

        if not self._is_relocatable:
            for parser_addr, symbols in parser_exports.items():
                if parser_addr in parser_addrs:
                    continue
                canon = self._disambiguate_export(symbols)
                # ARM THUMB: parser may use address - 1 (THUMB bit cleared)
                if self._is_func_start(parser_addr - 1):
                    if self._func_mangled_name(parser_addr - 1) in {s.name for s in symbols}:
                        continue
                logging.debug(
                    f"{self.log_prefix}: export {canon.name} @ {parser_addr:#x} "
                    f"not found in parser output"
                )
                call_graph[canon] = []
                if len(symbols) > 1:
                    for sym in symbols:
                        self._binary.replace_function(canon, sym, True)

        # Step 3 — build the call graph, resolving thunk trampolines.
        trampoline_map: dict[str, str] = {}
        # LIEF-confirmed imported names (.dynsym): distinguishes genuine PLT stubs
        # (IMPORTED + name in this set) from inlined C++ functions mis-classified
        # as external thunks by the disassembler (IMPORTED + name NOT in this set).
        lief_imported_names: set[str] = set(self._binary.imported_symbol_names)
        to_analyse = program_data

        while len(to_analyse) > 0:
            missed_data = dict()
            for func_data in to_analyse.values():
                exported = (
                    func_data.addr in parser_exports
                    or func_data.addr + 1 in parser_exports  # ARM THUMB
                )

                # Keep the function in the call graph when:
                # (a) it is a normal/library function,
                # (b) it is an exported or multi-callee thunk, OR
                # (c) it was classified IMPORTED by the disassembler but its
                #     name is absent from LIEF's imported-symbol table AND it
                #     is registered in the binary — the disassembler
                #     mis-classified an inlined C++ function (e.g. D0Ev
                #     deleting-destructor, virtual thunks) as an external
                #     stub.  Keeping it lets callers resolve it as a local
                #     call rather than generating an unresolved-callee error.
                #     The function_exists guard prevents promoting functions
                #     that were never registered (e.g. genuine C-linkage
                #     imports whose unmangled name happens to be absent from
                #     lief_imported_names).
                if (
                    func_data.type in (FuncType.LIBRARY, FuncType.NORMAL)
                    or (func_data.type == FuncType.THUNK and (exported or len(func_data.calls) > 1))
                    or (
                        func_data.type == FuncType.IMPORTED
                        and func_data.name not in lief_imported_names
                        and self._binary.function_exists(func_data.name)
                    )
                ):
                    call_graph[func_data.symbol] = self._build_calls_list(func_data, program_data)
                    continue

                if func_data.type == FuncType.THUNK and len(func_data.calls) == 1:
                    if func_data.calls[0] not in program_data:
                        mangled_name = self._func_mangled_name(func_data.calls[0])
                        if mangled_name == "":
                            logging.warning("Nothing found ")
                            continue

                        func_symbol = Symbol(
                            name=mangled_name,
                            demangled_name=self._func_demangled_name(func_data.calls[0]),
                            is_func=True,
                            addr=func_data.calls[0],
                        )
                        self._binary.add_function(func_symbol)
                        func = FuncData(
                            symbol=func_symbol,
                            type=self._func_type(func_data.calls[0]),
                            calls=self._func_children(func_data.calls[0]),
                            callers=self._func_parents(func_data.calls[0]),
                        )
                        missed_data[func_data.calls[0]] = func
                        callee_data = func
                    else:
                        callee_data = program_data[func_data.calls[0]]
                    if callee_data.type == FuncType.IMPORTED:
                        # Keep the name of the thunk "strcpy, sprintf"
                        trampoline_name = func_data.name
                        destination_name = callee_data.name
                        # in case of nested functions (starting with _, keep the less nested one)
                        if _count_leading_underscores(trampoline_name) > _count_leading_underscores(
                            destination_name
                        ):
                            trampoline_name, destination_name = destination_name, trampoline_name
                    else:  # Forward the call to the underlying function name
                        trampoline_name = func_data.name
                        destination_name = callee_data.name
                    # Resolve chains: A→B, B→C becomes A→C
                    while (
                        destination_name in trampoline_map
                        and trampoline_map[destination_name] != destination_name
                    ):
                        destination_name = trampoline_map[destination_name]
                    # Do not record a trampoline substitution when the destination
                    # is a tool-generated synthetic name (e.g. "FUN_1234" or
                    # "sub_5678"): the disassembler could not identify the branch
                    # target, so replacing the original stub name with a synthetic
                    # placeholder would drop the cross-binary call edge entirely.
                    # Skipping the substitution leaves the stub name intact so
                    # fwmapper can still resolve it against exported_functions.
                    if not _SYNTHETIC_FUNC_NAME_RE.match(destination_name):
                        trampoline_map[trampoline_name] = destination_name
                        for key, val in trampoline_map.items():
                            if val == trampoline_name:
                                trampoline_map[key] = destination_name

                    # Only remove the thunk stub when it wraps a true external
                    # (IMPORTED) symbol — i.e. it is a genuine PLT stub.  Internal
                    # forwarding thunks (callee type is NORMAL or another THUNK)
                    # must stay registered in the binary so their callers can
                    # resolve them as local calls.
                    if callee_data.type != FuncType.IMPORTED:
                        continue

                elif func_data.type == FuncType.THUNK and not func_data.calls and func_data.callers:
                    # Terminal thunk with callers but no callees — keep it
                    continue

                # Remove functions not kept as exported/library/normal.
                # _Z-prefixed names are preserved: a statically linked binary can
                # contain a private copy of a C++ symbol also present in the
                # dynamic import table — removing it would break intra-binary edges.
                if func_data.name.startswith("_Z"):
                    continue
                if (
                    self._binary.function_exists(func_data.name)
                    and self._binary.get_function_by_name(func_data.name).addr == func_data.addr
                ):
                    self._binary.remove_function(func_data.name)
            to_analyse = missed_data
            program_data.update(missed_data)

        # Apply trampoline substitutions to the final call graph
        self._call_graph: dict[Symbol, list[str]] = {
            sym: [trampoline_map.get(c, c) for c in callees] for sym, callees in call_graph.items()
        }

        self._close_bin_parser()

    # ------------------------------------------------------------------
    # Useful public properties
    # ------------------------------------------------------------------

    @property
    def binary(self) -> Binary:
        """:return: the Binary produced by the parser."""
        return self._binary

    @property
    def call_graph(self) -> dict[Symbol, list[str]]:
        """:return: mapping from each Symbol to its list of callee names."""
        return self._call_graph

    # ------------------------------------------------------------------
    # Abstract interface — implemented by each parser backend
    # ------------------------------------------------------------------

    @abstractmethod
    def _initiate_bin_parser(self, root_directory: Path, file_path: Path, image_base: int = 0):
        """Open the binary parser and run any required analysis."""

    @abstractmethod
    def _close_bin_parser(self):
        """Close the binary parser and release all resources."""

    @abstractmethod
    def _is_func_start(self, addr: int) -> bool:
        """:return: True if *addr* (parser space) is the entry point of a function."""

    @abstractmethod
    def _iter_func_addr(self) -> Iterator[int]:
        """Yield the parser-space entry-point address of every known function."""

    @abstractmethod
    def _func_mangled_name(self, addr: int) -> str:
        """:return: the raw (mangled) name of the function at *addr*"""

    @abstractmethod
    def _func_demangled_name(self, addr: int) -> str:
        """:return: the demangled name of the function at *addr*"""

    @abstractmethod
    def _func_children(self, addr: int) -> list[int]:
        """:return: entry-point addresses of callees of the function at *addr*."""

    @abstractmethod
    def _func_parents(self, addr: int) -> list[int]:
        """:return: entry-point addresses of callers of the function at *addr*."""

    @abstractmethod
    def _func_type(self, addr: int) -> FuncType:
        """:return: the FuncType of the function at *addr*.

        Thunk stubs that resolve to external/imported functions must return
        ``FuncType.IMPORTED`` so the trampoline resolution in ``__init__``
        correctly forwards callers to the imported symbol name.
        """

    # ------------------------------------------------------------------
    # Concrete helpers
    # ------------------------------------------------------------------

    def _generate_lief_bin(self, root_directory: Path, file_path: Path) -> Binary:
        """Load the binary via LIEF and return a populated Binary object.

        :raises FsMapperError: on load failure or missing path information.
        """
        result = FileSystemImportsMapper.load_binary(root_directory, file_path)
        if isinstance(result, str):
            raise FsMapperError(result)
        lief_binary, _ = result
        if lief_binary.real_path is None:
            raise FsMapperError(f"{self.log_prefix}: real_path not set (skip)")
        if not lief_binary.real_path.exists():
            raise FsMapperError(f"{self.log_prefix}: executable not found (skip)")

        # Detect ET_REL (kernel modules, object files) via LIEF before the
        # raw LIEF object is discarded.  Stored on the instance so BinaryParser
        # can skip address-based export matching for relocatable binaries.
        return lief_binary

    def _build_calls_list(
        self,
        func: FuncData,
        call_graph: dict[int, FuncData],
    ) -> list[str]:
        """Given a function return its call list.

        It only contains functions that are contained in the call graph and have a name.

        :return: a list of string (function names)
        """
        res: list[str] = list()
        for callee in [call_graph[addr] for addr in func.calls if addr in call_graph]:
            if callee.name is not None and callee.name != "":
                res.append(callee.name)
            else:
                logging.warning(
                    f"{self.log_prefix}: {func.symbol} calls unnamed function @ {callee.addr:#08x}"
                )
        return res

    def _combine_program_analysis_binary(
        self,
        parser_exports: dict[int, list[Symbol]],
    ) -> dict[int, FuncData]:
        """Build a ``{parser_addr: FuncData}`` dict merging parser and LIEF data.

        For each function discovered by the parser:

        - If its parser-space address matches a LIEF export entry, the export
          Symbol is used.
        - Otherwise a new internal Symbol is created — unless the function name
          matches a known imported symbol (e.g. a PLT stub already tracked by
          LIEF as an import), in which case the function is skipped entirely.

        :param parser_exports: LIEF exports already remapped to parser space.
        :return: mapping from parser-space address to FuncData.
        """
        imported_names: set[str] = set(self._binary.imported_symbol_names)
        program_data: dict[int, FuncData] = {}

        for parser_addr in self._iter_func_addr():
            if parser_addr in parser_exports or parser_addr + 1 in parser_exports:
                # Exported function — adopt the LIEF symbol
                symbols = parser_exports.get(parser_addr, parser_exports.get(parser_addr + 1, []))
                func_symbol = self._disambiguate_export(symbols)
                parser_name = self._func_demangled_name(parser_addr)
                if parser_name != func_symbol.demangled_name:
                    logging.debug(
                        f"{self.log_prefix}: rename {parser_name} → {func_symbol.demangled_name}"
                    )
                if len(symbols) > 1:
                    for sym in symbols:
                        self._binary.replace_function(func_symbol, sym, True)
            else:
                # Internal function — create a new Symbol in parser space.
                mangled_name = self._func_mangled_name(parser_addr)
                # Skip LIEF-imported names except: (a) PLT thunks — must reach
                # Step 3 to build trampoline_map; (b) _Z-prefixed names — a
                # statically linked binary may contain a private copy of a symbol
                # whose mangled name also appears in the dynamic import table.
                if (
                    mangled_name in imported_names
                    and not mangled_name.startswith("_Z")
                    and self._func_type(parser_addr) != FuncType.THUNK
                ):
                    continue
                func_symbol = Symbol(
                    name=mangled_name,
                    demangled_name=self._func_demangled_name(parser_addr),
                    is_func=True,
                    addr=parser_addr,
                )
                self._binary.add_function(func_symbol)

            program_data[parser_addr] = FuncData(
                symbol=func_symbol,
                type=self._func_type(parser_addr),
                calls=self._func_children(parser_addr),
                callers=self._func_parents(parser_addr),
            )

        return program_data

    def _disambiguate_export(self, symbols: list[Symbol]) -> Symbol:
        """Choose the most appropriate Symbol when multiple share the same address.

        Prefers the shortest name that does not start with ``_``.
        Falls back to the globally shortest name if all names start with ``_``.
        """
        if len(symbols) == 1:
            return symbols[0]

        chosen: Symbol | None = None
        for sym in symbols:
            if sym.demangled_name.startswith("_"):
                continue
            if chosen is None or len(sym.demangled_name) < len(chosen.demangled_name):
                chosen = sym

        if chosen is None:
            logging.debug(
                f"{self.log_prefix}: all exports start with '_', "
                f"picking shortest: {[s.demangled_name for s in symbols]}"
            )
            chosen = min(symbols, key=lambda s: len(s.demangled_name))

        return chosen


# ======================================================================
# IDA Pro backend
# ======================================================================


class IDAParser(BinaryParser):
    """BinaryParser implementation using IDA Pro as the analysis backend."""

    def _initiate_bin_parser(self, root_directory: Path, file_path: Path, image_base: int = 0):
        """Open the IDA database, running auto-analysis if needed."""
        from ida_domain.database import Database, IdaCommandOptions

        self._ida_cached_func = None  # single-entry cache used by _get_ida_func
        self._ida_db = Database.open(
            str(root_directory / file_path),
            args=IdaCommandOptions(auto_analysis=True, new_database=False),
        )

    def _close_bin_parser(self):
        """Close the IDA database without saving."""
        self._ida_db.close(save=False)

    def _get_ida_func(self, addr: int):
        """:return: the IDA function at *addr*, using a single-entry cache."""
        if self._ida_cached_func is not None and addr == self._ida_cached_func.start_ea:
            return self._ida_cached_func
        return self._ida_db.functions.get_at(addr)

    def _is_func_start(self, addr: int) -> bool:
        """:return: True if *addr* is the entry point of a known IDA function."""
        from ida_domain.base import InvalidEAError

        try:
            if self._ida_cached_func is not None and addr == self._ida_cached_func.start_ea:
                return True
            func = self._ida_db.functions.get_at(addr)
            return func is not None and func.start_ea == addr
        except InvalidEAError:
            return False

    def _iter_func_addr(self) -> Iterator[int]:
        """Yield the entry-point address of every function known to IDA.

        IDA's function list includes ``FUNC_TAIL`` entries (flag ``0x400``) —
        non-contiguous tail chunks that belong to a parent function defined
        elsewhere.  These are not callable entry points: they share their
        mangled name with the parent, making ``add_function`` overwrite
        ``internal_functions`` with the chunk address and breaking
        ``function_exists`` lookups for the real function.  They must be
        skipped so only true function starts enter ``program_data``.
        """
        from ida_domain.functions import FunctionFlags

        for func in self._ida_db.functions.get_all():
            flags = self._ida_db.functions.get_flags(func)
            if FunctionFlags.TAIL in flags:
                continue
            self._ida_cached_func = func
            yield func.start_ea

    def _get_import(self, addr: int) -> str | None:
        res = self._ida_db.functions.get_at(addr)
        if res:
            return res.name
        return None

    def _func_mangled_name(self, addr: int) -> str:
        """:return: the raw name of the function at *addr*, or ``sub_<ADDR>``."""
        func = self._get_ida_func(addr)
        import_info = self._ida_db.imports.get_import_at(addr)
        if import_info is not None and import_info.name is not None:
            return import_info.name
        if func is not None:
            name = self._ida_db.functions.get_name(func)
            if name:
                return name
        return f"sub_{addr:X}"

    def _func_demangled_name(self, addr: int) -> str:
        """:return: the demangled name, falling back to the mangled name."""
        mangled = self._func_mangled_name(addr)
        demangled = self._ida_db.names.demangle_name(mangled)
        return demangled if demangled is not None else mangled

    def _func_children(self, addr: int) -> list[int]:
        """:return: parser-space addresses of callees of the function at *addr*.

        When IDA's ``get_callees`` returns a ``FUNC_TAIL`` chunk (a
        non-contiguous piece of a parent function, flag ``0x400``), the chunk
        address is not a valid callable entry point and must not enter
        ``program_data``.  Instead, follow the chunk's own callee list to
        obtain the real parent function's ``start_ea`` and use that.  This
        ensures calls to tail-chunked functions are recorded against the true
        entry point that ``_iter_func_addr`` emitted.
        """
        from ida_domain.functions import FunctionFlags

        func = self._get_ida_func(addr)
        if func is None:
            return []
        result: list[int] = []
        for callee in self._ida_db.functions.get_callees(func):
            flags = self._ida_db.functions.get_flags(callee)
            if FunctionFlags.TAIL in flags:
                # Resolve to the real parent entry point via the chunk's callees.
                parents = list(self._ida_db.functions.get_callees(callee))
                if parents and parents[0].start_ea != callee.start_ea:
                    result.append(parents[0].start_ea)
                # If the chunk calls itself (unresolvable), drop it silently.
            else:
                result.append(callee.start_ea)
        return result

    def _func_parents(self, addr: int) -> list[int]:
        """:return: parser-space addresses of callers of the function at *addr*."""
        func = self._get_ida_func(addr)
        if func is None:
            return []
        return [caller.start_ea for caller in self._ida_db.functions.get_callers(func)]

    def _func_type(self, addr: int) -> FuncType:
        """:return: the FuncType of the function at *addr*.

        Thunks whose sole callee is an imported symbol are classified as
        ``IMPORTED`` so the trampoline resolution correctly forwards callers.
        """
        from ida_domain.functions import FunctionFlags

        func = self._get_ida_func(addr)
        if func is None:
            return FuncType.NORMAL

        flags = self._ida_db.functions.get_flags(func)
        is_imported = False

        callees = list(self._ida_db.functions.get_callees(func))
        if len(callees) == 0:
            if self._ida_db.imports.get_import_at(addr):
                is_imported = True

        if is_imported or len(func.name.split("@@")) == 2:  # symbols with a specific version:
            return FuncType.IMPORTED
        elif FunctionFlags.THUNK in flags:
            callees = list(self._ida_db.functions.get_callees(func))
            if len(callees) == 1:
                callee_name = self._ida_db.functions.get_name(callees[0])
                if self._ida_db.imports.exists(callee_name):
                    return FuncType.IMPORTED
            return FuncType.THUNK
        elif FunctionFlags.LIB in flags:
            return FuncType.LIBRARY
        return FuncType.NORMAL


# ======================================================================
# Ghidra backend
# ======================================================================

# Analyzers required for call-graph extraction (function discovery, xrefs,
# thunk resolution, import/export tables, and name demangling).
# Everything else is explicitly disabled to minimise analysis time.
_GHIDRA_REQUIRED_ANALYZERS: frozenset[str] = frozenset(
    [
        # --- Function discovery ---
        "Disassemble Entry Points",
        "Function Start Search",
        "Function Start Search After Code",
        "Non-Returning Functions - Discovered",
        "Non-Returning Functions - Known",
        # --- Call graph / cross-references ---
        "Call Convention ID",
        "Call-Fixup Installer",
        "Subroutine References",
        "Subroutine References - One Time",
        # --- Thunk resolution ---
        "Thunk Function",
        # --- Format-specific import/export tables ---
        # ELF
        "ELF Scalar Operand References",
        "External Entry References",
        # PE
        "PE Entry Point",
        "Windows x86 PE Thunk Functions",
        # Mach-O  (no extra analyzer needed beyond the loader itself)
        # --- Demangling ---
        "Demangler GNU",
        "Demangler Microsoft",
    ]
)


class GhidraParser(BinaryParser):
    """BinaryParser backed by Ghidra 12.0+ via PyGhidra."""

    def _initiate_bin_parser(self, root_directory: Path, file_path: Path, image_base: int = 0):
        """Start the JVM, open the binary with only the required analyzers, and initialise handles.

        All Ghidra analyzers not listed in ``_GHIDRA_REQUIRED_ANALYZERS`` are
        disabled before analysis runs, which significantly reduces analysis time
        while preserving full function-discovery and call-graph accuracy.

        Analyzer selection is done via ``program.getOptions("Analyzers")`` and
        ``setBoolean``, which is the stable public API across all Ghidra versions
        supported by PyGhidra.  No internal ``AutoAnalysisManager`` import is
        needed.
        """
        import os
        import tempfile

        import pyghidra  # type: ignore

        # Initialise all attributes upfront so _close_bin_parser is always safe
        self._pyghidra_ctx = None
        self._ghidra_program = None
        self._ghidra_project_dir: Path | None = None
        self._ghidra_func_manager = None
        self._ghidra_symbol_table = None
        self._ghidra_demangler = None
        self._ghidra_cached_func = None
        self._ghidra_load_base: int = 0
        self._ghidra_monitor = None
        self._ghidra_exported_parser_addrs: set[int] = set()
        self._ghidra_is_relocatable: bool = False
        self._ghidra_exported_names: dict[str, Symbol] = {}

        full_path = root_directory / file_path
        self._ghidra_project_dir = Path(tempfile.mkdtemp(prefix=f"ghidra_{os.getpid()}_"))

        # Start the JVM once per worker process (no-op if already running)
        if not pyghidra.started():
            from pyghidra.launcher import HeadlessPyGhidraLauncher  # type: ignore

            launcher = HeadlessPyGhidraLauncher()
            launcher.add_vmargs("-Xms512m", "-Xmx2g", "-XX:+UseG1GC")
            launcher.start()

        # Ghidra imports must come after JVM start
        from ghidra.app.util.demangler.gnu import GnuDemangler  # type: ignore
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore

        self._ghidra_monitor = ConsoleTaskMonitor()

        # Open without running analysis yet so we can configure the analyzer set.
        self._pyghidra_ctx = pyghidra.open_program(
            str(full_path),
            project_location=str(self._ghidra_project_dir),
            project_name="p",
            analyze=False,
        )
        flat_api = self._pyghidra_ctx.__enter__()
        program = flat_api.getCurrentProgram()

        # Disable every analyzer not in the required set via the stable
        # "Analyzers" options block, then trigger analysis through the flat API.
        analyzer_options = program.getOptions("Analyzers")
        for option_name in analyzer_options.getOptionNames():
            enabled = option_name in _GHIDRA_REQUIRED_ANALYZERS
            try:
                analyzer_options.setBoolean(option_name, enabled)
            except Exception:
                # Some option names in the "Analyzers" block are not simple
                # booleans (e.g. sub-option strings); skip them silently.
                pass
            if not enabled:
                logging.debug(f"{self.log_prefix}: disabled Ghidra analyzer '{option_name}'")

        # Run analysis with the filtered analyzer set via the stable flat API.
        flat_api.analyzeAll(program)

        self._ghidra_program = program
        # Derive load base from the program itself, not from LIEF's image_base,
        # so that _to_ghidra_address / _to_parser_addr are always consistent.
        self._ghidra_load_base = program.getImageBase().getOffset()
        # Build the exported-address set once so _func_type can check it cheaply.
        self._ghidra_exported_parser_addrs = {
            lief_addr - self._binary.image_base for lief_addr in self._binary.exported_funcs_by_addr
        }
        self._ghidra_func_manager = program.getFunctionManager()
        self._ghidra_symbol_table = program.getSymbolTable()

        # ET_REL (kernel modules, object files): Ghidra lays sections out in a
        # fake address space starting at 0x10000; LIEF reports raw
        # section-relative offsets.  The two coordinate systems are
        # incompatible, so address-based matching is impossible — we must match
        # exported symbols by name instead.
        # The "relocatable" flag is written by ElfProgramBuilder into the
        # program's PROGRAM_INFO options block under the key used by
        # RelocationTable.RELOCATABLE_PROP_NAME ("Relocatable").  We read it
        # directly as a string to avoid importing the internal class.
        self._ghidra_is_relocatable = bool(
            program.getOptions(program.PROGRAM_INFO).getBoolean("Relocatable", False)
        )
        # Name → LIEF Symbol map, populated only for relocatable binaries.
        self._ghidra_exported_names = (
            {
                sym.name: sym
                for symbols in self._binary.exported_funcs_by_addr.values()
                for sym in symbols
            }
            if self._ghidra_is_relocatable
            else {}
        )

        demangler = GnuDemangler()
        self._ghidra_demangler = demangler if demangler.canDemangle(program) else None

    def _close_bin_parser(self):
        """Exit the PyGhidra context and delete the temporary project directory."""
        import shutil

        if self._pyghidra_ctx is not None:
            try:
                self._pyghidra_ctx.__exit__(None, None, None)
            except Exception:
                pass
        if self._ghidra_project_dir is not None:
            shutil.rmtree(self._ghidra_project_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _to_ghidra_address(self, parser_addr: int):
        """Convert a parser-space address to a Ghidra ``Address`` object.

        Adds ``_ghidra_load_base`` to restore the absolute Ghidra address, then
        masks to a signed 64-bit integer to satisfy JPype's type requirements.
        """
        abs_addr = (parser_addr + self._ghidra_load_base) & 0xFFFFFFFFFFFFFFFF
        if abs_addr >= 0x8000000000000000:
            abs_addr -= 0x10000000000000000
        return (
            self._ghidra_program.getAddressFactory().getDefaultAddressSpace().getAddress(abs_addr)
        )

    def _to_parser_addr(self, ghidra_offset: int) -> int:
        """Convert an absolute Ghidra address offset to parser space."""
        return ghidra_offset - self._ghidra_load_base

    def _get_ghidra_func(self, parser_addr: int):
        """:return: the Ghidra Function at *parser_addr*, with a single-entry cache.

        Falls back to ``getFunctionContaining`` when ``getFunctionAt`` returns
        ``None``, which handles the ARM THUMB case where the parser address
        may be offset by one from the real entry point stored by Ghidra.
        """
        if (
            self._ghidra_cached_func is not None
            and self._to_parser_addr(self._ghidra_cached_func.getEntryPoint().getOffset())
            == parser_addr
        ):
            return self._ghidra_cached_func

        ghidra_addr = self._to_ghidra_address(parser_addr)
        func = self._ghidra_func_manager.getFunctionAt(ghidra_addr)
        if func is None:
            # getFunctionContaining handles mid-function addresses and the ARM
            # THUMB ±1 offset; only accept the result when the entry point
            # matches exactly (after rounding) to avoid false positives.
            func = self._ghidra_func_manager.getFunctionContaining(ghidra_addr)
            if func is not None:
                entry_parser_addr = self._to_parser_addr(func.getEntryPoint().getOffset())
                if abs(entry_parser_addr - parser_addr) > 1:
                    func = None

        if func is not None:
            self._ghidra_cached_func = func
        return func

    # ------------------------------------------------------------------
    # BinaryParser interface
    # ------------------------------------------------------------------

    def _combine_program_analysis_binary(
        self,
        parser_exports: dict[int, list[Symbol]],
    ) -> dict[int, FuncData]:
        """Override for relocatable binaries (ET_REL, e.g. kernel modules).

        For ``ET_REL`` files Ghidra places sections in a fake address space
        (default base ``0x10000``) while LIEF reports raw section-relative
        offsets.  Address-based matching is therefore impossible and exported
        symbols are matched by name instead.

        For non-relocatable binaries the base-class implementation is used
        unchanged.

        :param parser_exports: LIEF exports already remapped to parser space.
        :return: mapping from parser-space address to FuncData.
        """
        if not self._ghidra_is_relocatable:
            return super()._combine_program_analysis_binary(parser_exports)

        imported_names: set[str] = set(self._binary.imported_symbol_names)
        program_data: dict[int, FuncData] = {}

        for parser_addr in self._iter_func_addr():
            mangled_name = self._func_mangled_name(parser_addr)

            if mangled_name in self._ghidra_exported_names:
                # ET_REL: adopt name and demangled name from the LIEF export
                # symbol, but use the Ghidra parser-space address so that the
                # rest of BinaryParser sees a consistent address space.
                # The LIEF address is a raw section-relative offset and must
                # not be used as a key anywhere in the resolution logic.
                # Use add_exported_symbol so the symbol stays in exported_functions
                # (consistent with what load_binary registered via LIEF) and is
                # evicted from internal_functions if it was registered there first.
                lief_sym = self._ghidra_exported_names[mangled_name]
                func_symbol = Symbol(
                    name=lief_sym.name,
                    demangled_name=lief_sym.demangled_name,
                    is_func=True,
                    addr=parser_addr,
                )
                parser_name = self._func_demangled_name(parser_addr)
                if parser_name != func_symbol.demangled_name:
                    logging.debug(
                        f"{self.log_prefix}: rename {parser_name} → {func_symbol.demangled_name}"
                    )
                self._binary.add_exported_symbol(func_symbol)
            else:
                # Internal function — same guard as base class.
                if (
                    mangled_name in imported_names
                    and not mangled_name.startswith("_Z")
                    and self._func_type(parser_addr) != FuncType.THUNK
                ):
                    continue
                func_symbol = Symbol(
                    name=mangled_name,
                    demangled_name=self._func_demangled_name(parser_addr),
                    is_func=True,
                    addr=parser_addr,
                )
                self._binary.add_function(func_symbol)

            program_data[parser_addr] = FuncData(
                symbol=func_symbol,
                type=self._func_type(parser_addr),
                calls=self._func_children(parser_addr),
                callers=self._func_parents(parser_addr),
            )

        return program_data

    def _is_func_start(self, addr: int) -> bool:
        """:return: True if *addr* (parser space) is a known Ghidra function entry."""
        return self._get_ghidra_func(addr) is not None

    def _iter_func_addr(self) -> Iterator[int]:
        """Yield parser-space entry-point addresses of every non-external Ghidra function.

        ``getFunctions(True)`` skips functions that live in Ghidra's external
        program space (imported stubs resolved to library addresses).  Those are
        handled separately by the LIEF import tracking in ``BinaryParser``.
        """
        seen_addrs: set[int] = set()
        for func in self._ghidra_func_manager.getFunctions(True):
            # Skip external-space functions — they are not mapped in the binary.
            if func.isExternal():
                continue
            self._ghidra_cached_func = func
            parser_addr = self._to_parser_addr(func.getEntryPoint().getOffset())
            if parser_addr in seen_addrs:
                continue
            seen_addrs.add(parser_addr)
            yield parser_addr

    def _func_mangled_name(self, addr: int) -> str:
        """:return: the raw mangled name of the function at *addr*, or ``sub_<ADDR>``.

        Queries the symbol table directly for symbols whose name starts with
        ``_Z`` (Itanium ABI mangled prefix) at the given address, which gives
        the raw mangled name before Ghidra's demangler has processed it.
        Falls back to ``func.getName()`` for non-C++ functions, rejecting names
        that look like partial demangles (operators, destructors, anonymous).
        """
        func = self._get_ghidra_func(addr)
        if func is None:
            return f"FUN_{addr:X}"

        # Search all symbols at this address for a mangled (_Z...) name.
        ghidra_addr = self._to_ghidra_address(addr)
        for sym in self._ghidra_symbol_table.getSymbols(ghidra_addr):
            raw = sym.getName()
            if raw and raw.startswith("_Z"):
                return raw

        # No mangled symbol found — use func.getName() but reject partial
        # demangles: operators, destructors, and anonymous constructs.
        name = func.getName()
        if name and not (
            name.startswith("~")
            or name.startswith("operator")
            or (name.startswith("<") and name.endswith(">"))
        ):
            return name

        return f"FUN_{addr:X}"

    def _func_demangled_name(self, addr: int) -> str:
        """:return: the demangled name, falling back to the mangled name."""
        mangled = self._func_mangled_name(addr)
        if self._ghidra_demangler is not None:
            try:
                result = self._ghidra_demangler.demangle(mangled, True)
                if result is not None:
                    # Use getName() to get the bare function name without return
                    # type or parameter signature, so it matches the short callee
                    # names used in the call graph (e.g. "basic_string" rather
                    # than "std::__cxx11::basic_string<char, ...>").
                    name = result.getName()
                    if name:
                        return name
            except Exception:
                pass
        return mangled

    def _func_children(self, addr: int) -> list[int]:
        """:return: parser-space addresses of callees of the function at *addr*.

        Uses Ghidra's reference manager to collect raw CALL instruction targets
        rather than ``getCalledFunctions()``.  ``getCalledFunctions()`` resolves
        thunk chains and returns the *external* symbol directly, bypassing the
        PLT stub that lives in the binary's address space.  By reading raw call
        references we obtain the actual branch targets — including PLT thunk
        addresses — so the trampoline resolution in ``BinaryParser`` can
        correctly classify them as ``IMPORTED`` and forward callers to the
        imported symbol name.
        """
        func = self._get_ghidra_func(addr)
        if func is None:
            return []

        listing = self._ghidra_program.getListing()
        seen: set[int] = set()
        result: list[int] = []
        for cu in listing.getCodeUnits(func.getBody(), True):
            for ref in cu.getReferencesFrom():
                if not ref.getReferenceType().isCall():
                    continue
                target_offset = ref.getToAddress().getOffset()
                parser_addr = self._to_parser_addr(target_offset)
                if parser_addr in seen:
                    continue
                seen.add(parser_addr)
                result.append(parser_addr)
        return result

    def _func_parents(self, addr: int) -> list[int]:
        """:return: parser-space addresses of callers of the function at *addr*."""
        func = self._get_ghidra_func(addr)
        if func is None:
            return []

        seen: set[str] = set()
        result: list[int] = []
        for caller in func.getCallingFunctions(self._ghidra_monitor):
            if caller.isExternal():
                continue
            name = caller.getName()
            if name in seen:
                continue
            seen.add(name)
            result.append(self._to_parser_addr(caller.getEntryPoint().getOffset()))
        return result

    def _func_type(self, addr: int) -> FuncType:
        """:return: the FuncType of the function at *addr* (parser space)."""
        func = self._get_ghidra_func(addr)
        if func is None:
            return FuncType.NORMAL

        if func.isExternal():
            return FuncType.IMPORTED

        if func.isThunk():
            # Always THUNK — the trampoline resolution in Step 3 detects the
            # external callee via callee_data.type and collapses the chain.
            return FuncType.THUNK

        return FuncType.NORMAL
