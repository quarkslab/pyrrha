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
from pathlib import Path
from typing import NamedTuple

from pyrrha_mapper.backend import IDA, Backend, Ghidra
from pyrrha_mapper.common import Binary, Symbol
from pyrrha_mapper.exceptions import FsMapperError
from pyrrha_mapper.fs import FileSystemImportsMapper
from pyrrha_mapper.types import FuncType


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


class BinaryParser(Backend):
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
        super().__init__(
            file_path, root_directory, decompilation=False, image_base=self._binary.image_base
        )

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
        parser_addrs: set[int] = set(self.func_addrs)
        call_graph: dict[Symbol, list[str]] = {}

        if not self._is_relocatable:
            for parser_addr, symbols in parser_exports.items():
                if parser_addr in parser_addrs:
                    continue
                canon = self._disambiguate_export(symbols)
                # ARM THUMB: parser may use address - 1 (THUMB bit cleared)
                if self.is_func_start(parser_addr - 1):
                    if self.func_mangled_name(parser_addr - 1) in {s.name for s in symbols}:
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
                        mangled_name = self.func_mangled_name(func_data.calls[0])
                        if mangled_name == "":
                            logging.warning("Nothing found ")
                            continue

                        func_symbol = Symbol(
                            name=mangled_name,
                            demangled_name=self.func_demangled_name(func_data.calls[0]),
                            is_func=True,
                            addr=func_data.calls[0],
                        )
                        self._binary.add_function(func_symbol)
                        func = FuncData(
                            symbol=func_symbol,
                            type=self.func_type(func_data.calls[0]),
                            calls=self.func_children(func_data.calls[0]),
                            callers=self.func_parents(func_data.calls[0]),
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

        self.close()

    # ------------------------------------------------------------------
    # Public properties
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

        for parser_addr in self.func_addrs:
            if parser_addr in parser_exports or parser_addr + 1 in parser_exports:
                # Exported function — adopt the LIEF symbol.
                symbols = parser_exports.get(parser_addr, parser_exports.get(parser_addr + 1, []))
                func_symbol = self._disambiguate_export(symbols)
                parser_name = self.func_demangled_name(parser_addr)
                if parser_name != func_symbol.demangled_name:
                    logging.debug(
                        f"{self.log_prefix}: rename {parser_name} → {func_symbol.demangled_name}"
                    )
                if len(symbols) > 1:
                    for sym in symbols:
                        self._binary.replace_function(func_symbol, sym, True)
            else:
                # Internal function — create a new Symbol in parser space.
                mangled_name = self.func_mangled_name(parser_addr)
                # Skip LIEF-imported names except: (a) PLT thunks — must reach
                # Step 3 to build trampoline_map; (b) _Z-prefixed names — a
                # statically linked binary may contain a private copy of a symbol
                # whose mangled name also appears in the dynamic import table.
                if (
                    mangled_name in imported_names
                    and not mangled_name.startswith("_Z")
                    and self.func_type(parser_addr) != FuncType.THUNK
                ):
                    continue
                func_symbol = Symbol(
                    name=mangled_name,
                    demangled_name=self.func_demangled_name(parser_addr),
                    is_func=True,
                    addr=parser_addr,
                )
                self._binary.add_function(func_symbol)

            program_data[parser_addr] = FuncData(
                symbol=func_symbol,
                type=self.func_type(parser_addr),
                calls=self.func_children(parser_addr),
                callers=self.func_parents(parser_addr),
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


class IDABinaryParser(BinaryParser, IDA):
    """Binary parser backed by IDA Pro."""

    pass


class GhidraBinaryParser(BinaryParser, Ghidra):
    """Binary parser backed by Ghidra."""

    def __init__(self, *args, **kwargs)-> None:
        super().__init__(*args, **kwargs)
        program = self._ghidra_program

        # Build the exported-address set once so _func_type can check cheaply.
        self._ghidra_exported_parser_addrs: set[int] = {
            lief_addr - self._binary.image_base for lief_addr in self._binary.exported_funcs_by_addr
        }

        # ET_REL (kernel modules, object files): Ghidra lays sections out at a
        # fake base (0x10000); LIEF reports raw section-relative offsets.
        # The two coordinate systems are incompatible — match by name instead.
        self._ghidra_is_relocatable: bool = bool(
            program.getOptions(program.PROGRAM_INFO).getBoolean("Relocatable", False) # type: ignore
        )
        # Name → LIEF Symbol map, populated only for relocatable binaries.
        self._ghidra_exported_names: dict = (
            {
                sym.name: sym
                for symbols in self._binary.exported_funcs_by_addr.values()
                for sym in symbols
            }
            if self._ghidra_is_relocatable
            else {}
        )

    def _combine_program_analysis_binary(self, parser_exports: dict) -> dict:
        """Override for relocatable binaries (ET_REL, e.g. kernel modules).

        For ``ET_REL`` files Ghidra places sections in a fake address space
        while LIEF reports raw section-relative offsets.  Address-based
        matching is impossible — exported symbols are matched by name instead.
        For non-relocatable binaries the base-class implementation is used.

        :param parser_exports: LIEF exports already remapped to parser space.
        :return: mapping from parser-space address to FuncData.
        """
        # Only GhidraParser sets _ghidra_is_relocatable; GhidraLoader doesn't
        # call BaseParser.__init__ so this method is never reached from there.
        if not getattr(self, "_ghidra_is_relocatable", False):
            return super()._combine_program_analysis_binary(parser_exports)

        imported_names: set[str] = set(self._binary.imported_symbol_names)
        program_data: dict[int, FuncData] = {}

        for parser_addr in self.func_addrs:
            mangled_name = self.func_mangled_name(parser_addr)

            if mangled_name in self._ghidra_exported_names:
                # ET_REL: adopt name/demangled from the LIEF export symbol but
                # use the Ghidra parser-space address so the rest of BaseParser
                # sees a consistent address space.
                lief_sym = self._ghidra_exported_names[mangled_name]
                func_symbol = Symbol(
                    name=lief_sym.name,
                    demangled_name=lief_sym.demangled_name,
                    is_func=True,
                    addr=parser_addr,
                )
                parser_name = self.func_demangled_name(parser_addr)
                if parser_name != func_symbol.demangled_name:
                    logging.debug(
                        f"{getattr(self, 'log_prefix', '')}: "
                        f"rename {parser_name} → {func_symbol.demangled_name}"
                    )
                self._binary.add_exported_symbol(func_symbol)
            else:
                if (
                    mangled_name in imported_names
                    and not mangled_name.startswith("_Z")
                    and self.func_type(parser_addr) != FuncType.THUNK
                ):
                    continue
                func_symbol = Symbol(
                    name=mangled_name,
                    demangled_name=self.func_demangled_name(parser_addr),
                    is_func=True,
                    addr=parser_addr,
                )
                self._binary.add_function(func_symbol)

            program_data[parser_addr] = FuncData(
                symbol=func_symbol,
                type=self.func_type(parser_addr),
                calls=self.func_children(parser_addr),
                callers=self.func_parents(parser_addr),
            )

        return program_data
