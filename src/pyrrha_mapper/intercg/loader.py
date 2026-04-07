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
        assert self.symbol.addr
        return self.symbol.addr


def _count_leading_underscores(name: str) -> int:
    """:return: the number of leading underscores/dots in name"""
    return len(name) - len(name.lstrip("_."))


class BinaryParser:
    """Abstract base class that parses a binary and extracts call-graph data.

    Subclasses implement the parser-specific methods (IDA, Ghidra, …).
    Adresses are the one used in the backend, which can differ from LIEF ones
    (relative vs virtual).
    """

    def __init__(self, root_directory: Path, file_path: Path) -> None:
        self.log_prefix = f"[binary parsing] {file_path.name}"
        self._binary = self._generate_lief_bin(root_directory, file_path)
        self._initiate_bin_parser(root_directory, file_path, self._binary.image_base)

        image_base = self._binary.image_base

        # Remap LIEF export addresses to parser space once.
        # Keys are parser-space addresses; values are lists of LIEF Symbols.
        parser_exports: dict[int, list[Symbol]] = {
            lief_addr - image_base: symbols
            for lief_addr, symbols in self._binary.exported_funcs_by_addr.items()
        }

        # ------------------------------------------------------------------
        # Step 1 — combine parser functions with LIEF export metadata
        # ------------------------------------------------------------------
        program_data: dict[int, FuncData] = self._combine_program_analysis_binary(parser_exports)

        # ------------------------------------------------------------------
        # Step 2 — find exported symbols not discovered by the parser and
        # add them to the call graph with an empty call list
        # ------------------------------------------------------------------
        parser_addrs: set[int] = set(self._iter_func_addr())
        call_graph: dict[Symbol, list[str]] = {}

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

        # ------------------------------------------------------------------
        # Step 3 — build the call graph, resolving thunk trampolines
        # ------------------------------------------------------------------
        # Maps a trampoline name → the canonical name it should forward to.
        trampoline_map: dict[str, str] = {}
        to_analyse = program_data

        while len(to_analyse) > 0:
            missed_data = dict()
            for func_data in to_analyse.values():
                exported = (
                    func_data.addr in parser_exports
                    or func_data.addr + 1 in parser_exports  # ARM THUMB
                )

                if func_data.type in (FuncType.LIBRARY, FuncType.NORMAL) or (
                    func_data.type == FuncType.THUNK and (exported or len(func_data.calls) > 1)
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
                    trampoline_map[trampoline_name] = destination_name
                    for key, val in trampoline_map.items():
                        if val == trampoline_name:
                            trampoline_map[key] = destination_name

                elif func_data.type == FuncType.THUNK and not func_data.calls and func_data.callers:
                    # Terminal thunk with callers but no callees — keep it
                    continue

                # Remove functions not kept as exported/library/normal
                if self._binary.get_function_by_name(func_data.name).addr == func_data.addr:
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
                # Internal function — create a new Symbol in parser space
                mangled_name = self._func_mangled_name(parser_addr)
                # Skip PLT stubs and functions already tracked as imports by LIEF
                if mangled_name in imported_names:
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
        """Yield the entry-point address of every function known to IDA."""
        for func in self._ida_db.functions.get_all():
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
            return import_info.name.split("@")[0]
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
        """:return: parser-space addresses of callees of the function at *addr*."""
        func = self._get_ida_func(addr)
        if func is None:
            return []
        return [callee.start_ea for callee in self._ida_db.functions.get_callees(func)]

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

        if is_imported:
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


class GhidraParser(BinaryParser):
    """BinaryParser backed by Ghidra 12.0+ via PyGhidra."""

    def _initiate_bin_parser(self, root_directory: Path, file_path: Path, image_base: int = 0):
        """Start the JVM, open and fully analyse the binary, and initialise handles."""
        import os
        import tempfile

        import pyghidra

        # Initialise all attributes upfront so _close_bin_parser is always safe
        self._pyghidra_ctx = None
        self._ghidra_program = None
        self._ghidra_project_dir: Path | None = None
        self._ghidra_func_manager = None
        self._ghidra_symbol_table = None
        self._ghidra_ext_manager = None
        self._ghidra_demangler = None
        self._ghidra_cached_func = None
        self._ghidra_load_base: int = 0
        self._ghidra_monitor = None
        self._ghidra_exported_parser_addrs: set[int] = set()

        full_path = root_directory / file_path
        self._ghidra_project_dir = Path(tempfile.mkdtemp(prefix=f"ghidra_{os.getpid()}_"))

        # Start the JVM once per worker process (no-op if already running)
        if not pyghidra.started():
            from pyghidra.launcher import HeadlessPyGhidraLauncher

            launcher = HeadlessPyGhidraLauncher()
            launcher.add_vmargs("-Xms512m", "-Xmx2g", "-XX:+UseG1GC")
            launcher.start()

        # Ghidra imports must come after JVM start
        from ghidra.app.util.demangler.gnu import GnuDemangler
        from ghidra.util.task import ConsoleTaskMonitor

        self._ghidra_monitor = ConsoleTaskMonitor()

        # open_program(analyze=True) runs full blocking analysis and correctly
        # populates all cross-references including the call graph.
        # Note: open_program is deprecated in PyGhidra 3.0 but is currently
        # the only reliable path for complete headless analysis.
        self._pyghidra_ctx = pyghidra.open_program(
            str(full_path),
            project_location=str(self._ghidra_project_dir),
            project_name="p",
            analyze=True,
        )
        flat_api = self._pyghidra_ctx.__enter__()
        program = flat_api.getCurrentProgram()

        self._ghidra_program = program
        # Derive load base from the program itself, not from LIEF's image_base,
        # so that _to_ghidra_address / _to_parser_addr are always consistent.
        self._ghidra_load_base = program.getImageBase().getOffset()
        # Build the exported-address set once so _func_type can check it cheaply.
        self._ghidra_exported_parser_addrs: set[int] = {
            lief_addr - self._binary.image_base for lief_addr in self._binary.exported_funcs_by_addr
        }
        self._ghidra_func_manager = program.getFunctionManager()
        self._ghidra_symbol_table = program.getSymbolTable()
        self._ghidra_ext_manager = program.getExternalManager()

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
        """:return: the raw name of the function at *addr*, or ``sub_<ADDR>``."""
        func = self._get_ghidra_func(addr)
        if func is not None:
            name = func.getName()
            if name:
                return name
        return f"sub_{addr:X}"

    def _func_demangled_name(self, addr: int) -> str:
        """:return: the demangled name, falling back to the mangled name."""
        mangled = self._func_mangled_name(addr)
        if self._ghidra_demangler is not None:
            try:
                result = self._ghidra_demangler.demangle(mangled, True)
                if result is not None:
                    return result.getSignature(False)
            except Exception:
                pass
        return mangled

    def _func_children(self, addr: int) -> list[int]:
        """:return: parser-space addresses of callees of the function at *addr*.

        External callees are not returned here — they are handled by
        ``_func_type`` classifying their PLT thunk stubs as ``FuncType.IMPORTED``.
        """
        func = self._get_ghidra_func(addr)
        if func is None:
            return []

        seen: set[str] = set()
        result: list[int] = []
        for callee in func.getCalledFunctions(self._ghidra_monitor):
            if callee.isExternal():
                continue
            name = callee.getName()
            if name in seen:
                continue
            seen.add(name)
            result.append(self._to_parser_addr(callee.getEntryPoint().getOffset()))
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
        """:return: the FuncType of the function at *addr* (parser space).

        Thunk stubs that resolve to external functions are classified as
        ``IMPORTED`` so the trampoline resolution in ``BinaryParser`` correctly
        forwards all callers to the imported symbol name.

        Exception: if the thunk is itself exported (i.e. it appears in the
        binary's export table), it must be kept as ``THUNK`` so that
        ``BinaryParser`` adds it to the call graph rather than silently
        dropping it.  ``IMPORTED`` is reserved for non-exported stubs whose
        only purpose is to forward calls to an external symbol.
        """
        func = self._get_ghidra_func(addr)
        if func is None:
            return FuncType.NORMAL

        if func.isExternal():
            return FuncType.IMPORTED

        if func.isThunk():
            # Resolve thunk chain; classify as IMPORTED only when the thunk is
            # not exported — exported thunks must remain visible in the call
            # graph so BinaryParser does not drop them.
            thunked = func.getThunkedFunction(True)
            if thunked is not None and thunked.isExternal():
                if addr not in self._ghidra_exported_parser_addrs:
                    return FuncType.IMPORTED
            return FuncType.THUNK

        # Heuristic: function in a namespace matching a known external library
        from ghidra.program.model.symbol import SourceType

        symbol = self._ghidra_symbol_table.getPrimarySymbol(self._to_ghidra_address(addr))
        if symbol is not None and symbol.getSource() == SourceType.ANALYSIS:
            namespace = func.getParentNamespace()
            if namespace is not None and self._ghidra_ext_manager.contains(namespace.getName(True)):
                return FuncType.LIBRARY

        return FuncType.NORMAL
