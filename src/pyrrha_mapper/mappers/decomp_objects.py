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
"""Serialisable export model for the decompilation mapper.

These pydantic models mirror the transient analysis structures of
``decomp_mapper`` (``Location``, ``FuncData``) but, unlike them, can be dumped
to / loaded from JSON.  The mapper keeps using the lightweight dataclass/
NamedTuple for the hot indexing loop; this module provides the serialisable
projection produced once at the end of a run (see
``ExportedDecompilation.from_mapper``).

All function addresses are expressed in **parser space** (the native address
space of the underlying tool — IDA, Ghidra, etc.), exactly as in the mapper.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from pydantic import (
    BaseModel,
    Field,
    SerializationInfo,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from pyrrha_mapper.types import FuncType

from .objects import Symbol

if TYPE_CHECKING:  # pragma: no cover
    from .decomp_mapper import DecompilMapper, FuncData, Location


class ExportedLocation(BaseModel):
    """Serialisable location of a word (or more) inside a decompiled source.

    Mirror of ``decomp_mapper.Location`` (a ``NamedTuple``) that can be dumped
    to and loaded from JSON.  Lines and columns are 1-based, matching the
    convention used by the mapper when it records symbol/reference locations.
    """

    start_line: int
    start_col: int
    end_line: int
    end_col: int

    @classmethod
    def from_location(cls, location: Location) -> Self:
        """:return: an ExportedLocation built from a mapper Location."""
        return cls(
            start_line=location.start_line,
            start_col=location.start_col,
            end_line=location.end_line,
            end_col=location.end_col,
        )

    def as_tuple(self) -> tuple[int, int, int, int]:
        """:return: the location as a ``(start_line, start_col, end_line, end_col)`` tuple."""
        return (self.start_line, self.start_col, self.end_line, self.end_col)

    # from https://github.com/pydantic/pydantic/discussions/2910
    def __lt__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) < tuple(other.model_dump().values())

    def __le__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) <= tuple(other.model_dump().values())

    def __gt__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) > tuple(other.model_dump().values())

    def __ge__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) >= tuple(other.model_dump().values())


class ExportedFunction(BaseModel):
    """Serialisable view of a single decompiled function.

    Mirror of ``decomp_mapper.FuncData``.  The underlying :class:`Symbol` is
    embedded directly; ``id``/``name``/``demangled_name``/``addr`` are exposed
    as delegating properties so this object offers the same read surface as
    ``FuncData``.
    """

    symbol: Symbol
    type: FuncType
    calls: list[int] = Field(default_factory=list)
    callers: list[int] = Field(default_factory=list)
    source: str = ""
    source_id: int | None = None
    declaration: ExportedLocation | None = None
    # Keyed by callee (parser-space) address, as in FuncData.source_calls_loc.
    source_calls_loc: dict[int, list[ExportedLocation]] = Field(default_factory=dict)

    @field_validator("symbol", mode="after")
    @classmethod
    def validate_symbol_is_func(cls, value: Symbol) -> Symbol:
        """Ensure the embedded symbol is a function."""
        if not value.is_func:
            raise ValueError(f"symbol '{value}' cannot back a function as 'is_func' is False")
        return value

    @property
    def id(self) -> int | None:
        """:return: the associated DB id if any."""
        return self.symbol.id

    @id.setter
    def id(self, val: int) -> None:
        self.symbol.id = val

    @property
    def name(self) -> str:
        """:return: mangled name of the function."""
        return self.symbol.name

    @property
    def demangled_name(self) -> str:
        """:return: demangled name of the function."""
        return self.symbol.demangled_name

    @property
    def addr(self) -> int:
        """:return: address of the function in the binary (parser space)."""
        assert self.symbol.addr is not None
        return self.symbol.addr

    @classmethod
    def from_func_data(cls, func: FuncData) -> Self:
        """:return: an ExportedFunction built from a mapper FuncData object."""
        declaration = (
            ExportedLocation.from_location(func.declaration)
            if func.declaration is not None
            else None
        )
        source_calls_loc = {
            callee_addr: [ExportedLocation.from_location(loc) for loc in locations]
            for callee_addr, locations in func.source_calls_loc.items()
        }
        return cls(
            symbol=func.symbol,
            type=func.type,
            calls=list(func.calls),
            callers=list(func.callers),
            source=func.source,
            source_id=func.source_id,
            declaration=declaration,
            source_calls_loc=source_calls_loc,
        )

    def __repr__(self):  # noqa: D105
        return f"ExportedFunction('{self.name}')"


class ExportedDecompilation(BaseModel):
    """Serialisable result of a single ``DecompilMapper`` run.

    It stores the analysed binary identity and the decompiled functions keyed
    by their parser-space entry-point address.  It is based on pydantic so it
    can be dumped to a dict/JSON and rebuilt from these dumps.
    """

    path: Path
    id: int | None = None
    name: str = ""
    functions: dict[int, ExportedFunction] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Enforce object name based on its path."""
        self.name = self.path.name

    # ----------------------------- Serialisation ---------------------------------

    @field_serializer("functions", mode="plain", when_used="always")
    def serialize_functions(
        self, v: dict[int, ExportedFunction], info: SerializationInfo
    ) -> dict[Any, Any]:
        """Serialize the address-keyed functions dict.

        JSON object keys must be strings, so integer addresses are stringified
        in JSON mode and kept as integers in python mode.
        """
        mode = "json" if info.mode_is_json() else "python"
        res: dict[Any, Any] = dict()
        for addr, func in v.items():
            key = str(addr) if info.mode_is_json() else addr
            res[key] = func.model_dump(mode=mode)
        return res

    @field_validator("functions", mode="before")
    @classmethod
    def validate_functions(cls, data: Any, info: ValidationInfo) -> Any:
        """Validate a dict dump and turn it into an ``int -> ExportedFunction`` dict.

        Accepts an already-built mapping, a python dump (int keys) or a JSON
        dump (string keys); the latter has its keys converted back to int.
        """
        if not isinstance(data, dict):
            raise ValueError("provided functions data is not a dict")
        res: dict[int, ExportedFunction] = dict()
        for addr, content in data.items():
            try:
                int_addr = int(addr)
            except (TypeError, ValueError) as e:
                raise ValueError(f"Cannot convert function key '{addr}' into an int: {e}") from e
            if isinstance(content, ExportedFunction):
                res[int_addr] = content
            else:
                res[int_addr] = ExportedFunction.model_validate(content)
        return res

    @model_validator(mode="after")
    def validate_keys_match_addr(self) -> Self:
        """Ensure each function is stored under its own address when it has one."""
        for addr, func in self.functions.items():
            if func.symbol.addr is not None and func.symbol.addr != addr:
                raise ValueError(
                    f"function '{func.name}' stored under address {addr} but its symbol "
                    f"address is {func.symbol.addr}"
                )
        return self

    def model_dump_json(self, **args) -> str:
        """Override classic pydantic model_dump_json with preselected arguments."""
        return json.dumps(self.model_dump(mode="json", **args))

    def write(self, export_path: Path) -> None:
        """Dump content of the instance into a JSON file."""
        export_path.write_text(self.model_dump_json())

    @classmethod
    def from_json_export(cls, export_path: Path | str) -> Self:
        """Create and populate an instance from a JSON file content."""
        export_path = Path(export_path)
        return cls.model_validate_json(export_path.read_text())

    @classmethod
    def from_mapper(cls, mapper: DecompilMapper) -> Self:
        """:return: an ExportedDecompilation built from a DecompilMapper run."""
        functions = {
            addr: ExportedFunction.from_func_data(func) for addr, func in mapper.functions.items()
        }
        return cls(path=mapper.bin.path, id=mapper.bin.id, functions=functions)

    # ----------------------------- Manipulation helpers ---------------------------

    def add_function(self, func: ExportedFunction) -> None:
        """Record a function, keyed by its address. Overrides any existing entry."""
        self.functions[func.addr] = func

    def function_exists(self, addr: int) -> bool:
        """:return: True if a function exists at the given address."""
        return addr in self.functions

    def function_name_exists(self, name: str) -> bool:
        """:return: True if a function with the given (mangled) name exists."""
        return any(func.name == name for func in self.functions.values())

    def get_function_by_addr(self, addr: int) -> ExportedFunction:
        """:return: the function recorded at the given address."""
        return self.functions[addr]

    def get_function_by_name(self, name: str) -> ExportedFunction:
        """:return: the first function with the given (mangled) name."""
        for func in self.functions.values():
            if func.name == name:
                return func
        raise KeyError(name)

    def iter_functions(self) -> Iterable[ExportedFunction]:
        """:return: an iterable over the functions of the binary."""
        yield from self.functions.values()

    def __repr__(self):  # noqa: D105
        return f"ExportedDecompilation('{self.path}', funcs={len(self.functions)})"
