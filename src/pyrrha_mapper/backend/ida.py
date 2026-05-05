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
"""IDA Pro backend implementation of Backend abstract interface."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from ida_domain.database import Database, IdaCommandOptions
from ida_domain.functions import FunctionFlags

from pyrrha_mapper.backend import Backend
from pyrrha_mapper.types import FuncType


class IDA(Backend):
    """IDA Pro backend."""

    def __init__(
        self,
        bin_path: Path,
        root_directory: Path | None,
        decompilation: bool = False,
        image_base: int = 0,
    ) -> None:
        self.decompilation_activated = decompilation
        self.image_base = image_base
        self._bin_path = bin_path
        self._ida_cached_func = None  # single-entry cache used by _get_ida_func
        self._ida_db: Database = Database.open(
            str(bin_path) if root_directory is None else str(root_directory / bin_path),
            args=IdaCommandOptions(auto_analysis=True, new_database=False),
        )

    def close(self) -> None:
        """Close the binary parser and release all resources."""
        self._ida_db.close(save=False)

    def is_func_start(self, addr: int) -> bool:
        """:return: True if *addr* (parser space) is the entry point of a function."""
        from ida_domain.base import InvalidEAError

        try:
            if self._ida_cached_func is not None and addr == self._ida_cached_func.start_ea:
                return True
            func = self._ida_db.functions.get_at(addr)
            return func is not None and func.start_ea == addr
        except InvalidEAError:
            return False

    @property
    def func_addrs(self) -> Iterator[int]:
        """Yield the parser-space entry-point address of every known function."""
        for func in self._ida_db.functions.get_all():
            if FunctionFlags.TAIL in self._ida_db.functions.get_flags(func):
                continue
            self._ida_cached_func = func
            yield func.start_ea

    def func_mangled_name(self, addr: int) -> str:
        """Return the raw (mangled) name of the function at *addr*.

        Resolution order:

        1. Import table — preferred for genuine PLT stubs so the name matches
           LIEF's :attr:`~pyrrha_mapper.common.Binary.imported_symbol_names`.
        2. ``get_name`` on the ``func_t`` — covers normal and library functions.
        3. ``sub_<ADDR>`` fallback when IDA could not recover any name.

        :param addr: function entry-point address.
        :return: mangled symbol name or ``sub_<ADDR>``.
        """
        func = self._get_ida_func(addr)
        import_info = self._ida_db.imports.get_import_at(addr)
        if import_info is not None and import_info.name is not None:
            return import_info.name
        if func is not None:
            name = self._ida_db.functions.get_name(func)
            if name:
                return name
        return f"sub_{addr:X}"

    def func_demangled_name(self, addr: int) -> str:
        """:return: the demangled name, falling back to the mangled name."""
        mangled = self.func_mangled_name(addr)
        demangled = self._ida_db.names.demangle_name(mangled)
        return demangled if demangled is not None else mangled

    def func_children(self, addr: int) -> list[int]:
        """Return parser-space addresses of callees of the function at *addr*.

        When IDA's ``get_callees`` returns a ``FUNC_TAIL`` chunk, the chunk's
        own callee list is followed one level to obtain the real parent
        ``start_ea``.  Unresolvable self-referential chunks are dropped silently.

        :param addr: function entry-point address.
        :return: list of callee entry-point addresses.
        """
        func = self._get_ida_func(addr)
        result: list[int] = []
        for callee in self._ida_db.functions.get_callees(func) if func is not None else []:
            if FunctionFlags.TAIL in self._ida_db.functions.get_flags(callee):
                parents = list(self._ida_db.functions.get_callees(callee))
                if parents and parents[0].start_ea != callee.start_ea:
                    result.append(parents[0].start_ea)
            else:
                result.append(callee.start_ea)
        return result

    def func_parents(self, addr: int) -> list[int]:
        """:return: parser-space addresses of callers of the function at *addr*."""
        func = self._get_ida_func(addr)
        if func is None:
            return []
        return [caller.start_ea for caller in self._ida_db.functions.get_callers(func)]

    def func_type(self, addr: int) -> FuncType:
        """:return: the FuncType of the function at *addr*.

        Classification order:

        1. No callees + present in import table → ``IMPORTED`` (bare PLT stub).
        2. Versioned symbol (``name@@VERSION``) → ``IMPORTED``.
        3. ``FUNC_THUNK`` + single callee whose name is a known import →
           ``IMPORTED`` (thunk wrapping an external symbol).
        4. ``FUNC_THUNK`` otherwise → ``THUNK``.
        5. ``FUNC_LIB`` → ``LIBRARY``.
        6. Default → ``NORMAL``.
        """
        func = self._get_ida_func(addr)
        if func is None:
            return FuncType.NORMAL

        flags = self._ida_db.functions.get_flags(func)
        callees = list(self._ida_db.functions.get_callees(func))

        if len(callees) == 0 and self._ida_db.imports.get_import_at(func.start_ea):
            return FuncType.IMPORTED
        if len(func.name.split("@@")) == 2:
            return FuncType.IMPORTED
        if FunctionFlags.THUNK in flags:
            if len(callees) == 1:
                callee_name = self._ida_db.functions.get_name(callees[0])
                if self._ida_db.imports.exists(callee_name):
                    return FuncType.IMPORTED
            return FuncType.THUNK
        if FunctionFlags.LIB in flags:
            return FuncType.LIBRARY
        return FuncType.NORMAL

    def func_decompiled(self, addr: int) -> str:
        """:return: decompilation result of the function"""
        result: dict[int, str] = {}
        func = self._get_ida_func(addr)
        if func is None:
            return ""
        try:
            lines = self._ida_db.functions.get_pseudocode(func, remove_tags=True)
        except RuntimeError as exc:
            logging.debug(
                f"[IDA] skipping {func.start_ea:#x} "
                f"({self._ida_db.functions.get_name(func)!r}): {exc}"
            )
            return ""
        logging.info(f"[IDA] decompiled {len(result)} functions from {self._bin_path}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal IDA method
    # ------------------------------------------------------------------

    def _get_ida_func(self, addr: int):
        """Return the IDA ``func_t`` at *addr*, using a single-entry cache.

        :param addr: function entry-point address.
        :return: the IDA ``func_t`` object, or ``None`` if not found.
        """
        if self._ida_cached_func is not None and addr == self._ida_cached_func.start_ea:
            return self._ida_cached_func
        return self._ida_db.functions.get_at(addr)

    @property
    def _ida_funcs(self) -> Iterator:
        """Yield every non-tail ``func_t`` in the IDA database.

        ``FUNC_TAIL`` entries are non-contiguous chunks that share the parent
        function's name and address space.  Yielding them would produce
        duplicate or misleading entries in any downstream mapping, so they are
        filtered out here at the source.

        :return: iterator of ``func_t`` objects with ``FUNC_TAIL`` excluded.
        """
        for func in self._ida_db.functions.get_all():
            if FunctionFlags.TAIL in self._ida_db.functions.get_flags(func):
                continue
            self._ida_cached_func = func
            yield func
