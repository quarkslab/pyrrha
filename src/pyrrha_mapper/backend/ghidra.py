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
"""Ghidra backend implementation of Backend abstract interface."""

import logging
import os
import re
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pyghidra

from pyrrha_mapper.backend import Backend
from pyrrha_mapper.types import FuncType

# Analyzers required for call-graph extraction.
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

# Additional analyzers required when the Ghidra decompiler is used to produce
# pseudocode (i.e. in GhidraLoader but NOT in GhidraParser).
#
#   Stack                    — stack-frame analysis; needed for correct local-
#                              variable naming in pseudocode (param_N / local_N).
#   Stack Variable References — accurate tracking of stack-slot references
#                              across basic blocks used by the decompiler.
#   Shared Return Calls      — identifies tail-call / shared-epilogue patterns;
#                              without it some call edges are absent from the
#                              decompiled output.
#   Data Type Propagation    — propagates inferred struct/pointer types through
#                              the program; without it the decompiler emits
#                              ``undefined *`` for most pointer arguments,
#                              making call-site name matching less reliable.
_GHIDRA_DECOMPILER_EXTRA_ANALYZERS: frozenset[str] = frozenset(
    [
        "Stack",
        "Stack Variable References",
        "Shared Return Calls",
        "Data Type Propagation",
    ]
)

# Tool-generated fallback names emitted by Ghidra when the real symbol name is
# unknown.  Callees matching this pattern cannot be resolved as meaningful
# targets and must be skipped.
#   FUN_<HEX>   unnamed Ghidra function
#   _INIT_<N>   ELF .init_array slot
#   _FINI_<N>   ELF .fini_array slot
_GHIDRA_SYNTHETIC_NAME_RE: re.Pattern[str] = re.compile(
    r"^(?:FUN_[0-9A-Fa-f]+|_INIT_\d+|_FINI_\d+)$"
)


class Ghidra(Backend):
    """Ghidra backend."""

    def __init__(
        self,
        bin_path: Path,
        root_directory: Path | None,
        decompilation: bool = False,
        image_base: int = 0,
        timeout = 600,
    ) -> None:
        """Open the binary parser and run any required analysis."""
        self.decompilation_activated = decompilation
        self.image_base = image_base
        self._timeout = timeout

        # Initialise all attributes upfront so _close_ghidra is always safe.
        self._pyghidra_ctx = None
        self._ghidra_program = None
        self._ghidra_project_dir: Path | None = None
        self._ghidra_func_manager = None
        self._ghidra_symbol_table = None
        self._ghidra_demangler = None
        self._ghidra_cached_func = None
        self._ghidra_load_base: int = 0
        self._ghidra_monitor = None

        self._ghidra_project_dir = Path(tempfile.mkdtemp(prefix=f"ghidra_{os.getpid()}_"))

        # Start the JVM once per worker process (no-op if already running).
        if not pyghidra.started():
            from pyghidra.launcher import HeadlessPyGhidraLauncher  # type: ignore

            launcher = HeadlessPyGhidraLauncher()
            launcher.add_vmargs("-Xms512m", "-Xmx2g", "-XX:+UseG1GC")
            launcher.start()

        # Ghidra imports must come after JVM start.
        from ghidra.app.decompiler import DecompInterface  # type: ignore
        from ghidra.app.util.demangler.gnu import GnuDemangler  # type: ignore
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore

        self._ghidra_monitor = ConsoleTaskMonitor()

        # Open without running analysis yet so we can configure the analyser set.
        self._pyghidra_ctx = pyghidra.open_program(
            str(bin_path) if root_directory is None else str(root_directory / bin_path),
            project_location=str(self._ghidra_project_dir),
            project_name="p",
            analyze=False,
        )
        flat_api = self._pyghidra_ctx.__enter__()
        program = flat_api.getCurrentProgram()

        # Build the effective analyser set and apply it.
        if self.decompilation_activated:
            active_analyzers = _GHIDRA_REQUIRED_ANALYZERS | _GHIDRA_DECOMPILER_EXTRA_ANALYZERS
        else:
            active_analyzers = _GHIDRA_REQUIRED_ANALYZERS
        analyzer_options = program.getOptions("Analyzers")
        for option_name in analyzer_options.getOptionNames():
            enabled = option_name in active_analyzers
            try:
                analyzer_options.setBoolean(option_name, enabled)
            except Exception:
                # Some option names are not simple booleans; skip them silently.
                pass

        flat_api.analyzeAll(program)

        self._ghidra_program = program
        # Derive load base from the program itself, not from LIEF's image_base,
        # so that _to_ghidra_address / _to_parser_addr are always consistent.
        self._ghidra_load_base = program.getImageBase().getOffset()
        self._ghidra_func_manager = program.getFunctionManager()
        self._ghidra_symbol_table = program.getSymbolTable()

        demangler = GnuDemangler()
        self._ghidra_demangler = demangler if demangler.canDemangle(program) else None

        if self.decompilation_activated:
            self.ifc = DecompInterface()
            self.ifc.openProgram(self._ghidra_program)
            self.monitor = ConsoleTaskMonitor()

    def close(self) -> None:
        """Close the binary parser and release all resources."""
        if self.decompilation_activated:
            self.ifc.dispose()
        if self._pyghidra_ctx is not None:
            try:
                self._pyghidra_ctx.__exit__(None, None, None)
            except Exception:
                pass
            self._pyghidra_ctx = None
        if self._ghidra_project_dir is not None:
            shutil.rmtree(self._ghidra_project_dir, ignore_errors=True)
            self._ghidra_project_dir = None

    def is_func_start(self, addr: int) -> bool:
        """:return: True if *addr* (parser space) is the entry point of a function."""
        return self._get_ghidra_func(addr) is not None

    @property
    def func_addrs(self) -> Iterator[int]:
        """Yield the parser-space entry-point address of every known function."""
        seen_addrs: set[int] = set()
        for func in self._ghidra_func_manager.getFunctions(True): # type: ignore
            if func.isExternal():
                continue
            self._ghidra_cached_func = func
            parser_addr = self._to_parser_addr(func.getEntryPoint().getOffset())
            if parser_addr in seen_addrs:
                continue
            seen_addrs.add(parser_addr)
            yield self._to_parser_addr(func.getEntryPoint().getOffset())

    def func_mangled_name(self, addr: int) -> str:
        """Return the raw (mangled) name of the function at *addr*.

        Queries the symbol table for ``_Z``-prefixed (Itanium ABI) symbols
        first, then falls back to ``func.getName()``, rejecting partial
        demangles.  Returns ``FUN_<ADDR>`` when no usable name is found.

        :param addr: function entry-point address in parser space.
        :return: mangled symbol name or ``FUN_<ADDR>``.
        """
        func = self._get_ghidra_func(addr)
        if func is None:
            return f"FUN_{addr:X}"

        ghidra_addr = self._to_ghidra_address(addr)
        for sym in self._ghidra_symbol_table.getSymbols(ghidra_addr): # type: ignore
            raw = sym.getName()
            if raw and raw.startswith("_Z"):
                return raw

        name = func.getName()
        if name and not (
            name.startswith("~")
            or name.startswith("operator")
            or (name.startswith("<") and name.endswith(">"))
        ):
            return name

        return f"FUN_{addr:X}"

    def func_demangled_name(self, addr: int) -> str:
        """Return the demangled name of the function at *addr*.

        Uses ``getName()`` on the ``DemangledObject`` (bare function name
        without return type or parameter signature).  Falls back to the
        mangled name when the demangler is unavailable or returns ``None``.

        :param addr: function entry-point address in parser space.
        :return: demangled name, or mangled name if demangling is unavailable.
        """
        mangled = self.func_mangled_name(addr)
        if self._ghidra_demangler is not None:
            try:
                result = self._ghidra_demangler.demangle(mangled, True)
                if result is not None:
                    name = result.getName()
                    if name:
                        return name
            except Exception:
                pass
        return mangled

    def func_children(self, addr: int) -> list[int]:
        """:return: entry-point addresses of callees of the function at *addr*."""
        func = self._get_ghidra_func(addr)
        if func is None:
            return []
        listing = self._ghidra_program.getListing() # type: ignore
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

    def func_parents(self, addr: int) -> list[int]:
        """:return: entry-point addresses of callers of the function at *addr*."""
        func = self._get_ghidra_func(addr)
        seen: set[str] = set()
        result: list[int] = []
        for caller in func.getCallingFunctions(self._ghidra_monitor) if func is not None else []:
            if caller.isExternal():
                continue
            name = caller.getName()
            if name in seen:
                continue
            seen.add(name)
            result.append(self._to_parser_addr(caller.getEntryPoint().getOffset()))
        return result

    def func_type(self, addr: int) -> FuncType:
        """:return: the FuncType of the function at *addr*.

        Thunk stubs that resolve to external/imported functions must return
        ``FuncType.IMPORTED`` so the trampoline resolution in ``__init__``
        correctly forwards callers to the imported symbol name.
        """
        func = self._get_ghidra_func(addr)
        if func is None:
            return FuncType.NORMAL
        if func.isExternal():
            return FuncType.IMPORTED
        if func.isThunk():
            return FuncType.THUNK
        return FuncType.NORMAL

    def func_decompiled(self, addr: int) -> str:
        """:return: decompilation result of the function"""
        assert self.decompilation_activated
        func = self._get_ghidra_func(addr)
        if func is None:
            return ""
        addr = self._to_parser_addr(func.getEntryPoint().getOffset())
        try:
            res = self.ifc.decompileFunction(func, self._timeout, self.monitor)
            if res is None or not res.decompileCompleted():
                return ""
            return str(res.getDecompiledFunction().getC())
        except Exception as exc:
            logging.debug(f"[Ghidra] skipping {addr:#x} ({self.func_mangled_name(addr)!r}): {exc}")
            return ""

    # ------------------------------------------------------------------
    # Shared Ghidra primitives
    # ------------------------------------------------------------------

    def _to_ghidra_address(self, parser_addr: int):
        """Convert a parser-space address to a Ghidra ``Address`` object.

        :param parser_addr: address in parser space.
        :return: Ghidra ``Address`` object.
        """
        abs_addr = (parser_addr + self._ghidra_load_base) & 0xFFFFFFFFFFFFFFFF
        if abs_addr >= 0x8000000000000000:
            abs_addr -= 0x10000000000000000
        return (
            self._ghidra_program.getAddressFactory().getDefaultAddressSpace().getAddress(abs_addr) # type: ignore
        )

    def _to_parser_addr(self, ghidra_offset: int) -> int:
        """Convert an absolute Ghidra address offset to parser space.

        :param ghidra_offset: raw offset returned by ``getOffset()``.
        :return: address in parser space.
        """
        return ghidra_offset - self._ghidra_load_base

    def _get_ghidra_func(self, parser_addr: int):
        """Return the Ghidra ``Function`` at *parser_addr*, using a single-entry cache.

        Falls back to ``getFunctionContaining`` when ``getFunctionAt`` returns
        ``None``, handling the ARM THUMB ±1 offset case.  Only accepts the
        fallback result when the entry point matches within ±1 byte.

        :param parser_addr: address in parser space.
        :return: Ghidra ``Function``, or ``None`` if not found.
        """
        if (
            self._ghidra_cached_func is not None
            and self._to_parser_addr(self._ghidra_cached_func.getEntryPoint().getOffset())
            == parser_addr
        ):
            return self._ghidra_cached_func

        ghidra_addr = self._to_ghidra_address(parser_addr)
        func = self._ghidra_func_manager.getFunctionAt(ghidra_addr) # type: ignore
        if func is None:
            func = self._ghidra_func_manager.getFunctionContaining(ghidra_addr) # type: ignore
            if func is not None:
                entry_parser_addr = self._to_parser_addr(func.getEntryPoint().getOffset())
                if abs(entry_parser_addr - parser_addr) > 1:
                    func = None

        if func is not None:
            self._ghidra_cached_func = func
        return func
