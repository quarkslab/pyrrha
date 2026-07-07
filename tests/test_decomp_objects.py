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
"""Unit tests for the decompilation export model (decomp_objects)."""

import json
from pathlib import Path

import pytest

from pyrrha_mapper.mappers.decomp_objects import (
    ExportedDecompilation,
    ExportedFunction,
    ExportedLocation,
)
from pyrrha_mapper.mappers.objects import Symbol
from pyrrha_mapper.types import FuncType

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def callee_symbol() -> Symbol:
    """:return: the symbol used as a callee function."""
    return Symbol(name="bar", demangled_name="bar", is_func=True, id=6, addr=0x2000)


@pytest.fixture
def caller_symbol() -> Symbol:
    """:return: the symbol used as a caller function."""
    return Symbol(name="foo", demangled_name="foo(int)", is_func=True, id=5, addr=0x1000)


@pytest.fixture
def declaration_loc() -> ExportedLocation:
    """:return: a location pointing at a function declaration."""
    return ExportedLocation(start_line=1, start_col=6, end_line=1, end_col=9)


@pytest.fixture
def call_loc() -> ExportedLocation:
    """:return: a location pointing at a call site."""
    return ExportedLocation(start_line=2, start_col=3, end_line=2, end_col=6)


@pytest.fixture
def callee_func(callee_symbol: Symbol) -> ExportedFunction:
    """:return: an ExportedFunction with no calls (a leaf callee)."""
    return ExportedFunction(symbol=callee_symbol, type=FuncType.NORMAL, source="void bar(){}")


@pytest.fixture
def caller_func(
    caller_symbol: Symbol, declaration_loc: ExportedLocation, call_loc: ExportedLocation
) -> ExportedFunction:
    """:return: an ExportedFunction that calls bar (addr 0x2000)."""
    return ExportedFunction(
        symbol=caller_symbol,
        type=FuncType.NORMAL,
        calls=[0x2000],
        callers=[],
        source="void foo(int a){\n  bar();\n}",
        source_id=9,
        declaration=declaration_loc,
        source_calls_loc={0x2000: [call_loc]},
    )


@pytest.fixture
def imported_func() -> ExportedFunction:
    """:return: an imported (extern) ExportedFunction with no source."""
    return ExportedFunction(
        symbol=Symbol(name="puts", demangled_name="puts", is_func=True, id=7, addr=0x3000),
        type=FuncType.IMPORTED,
    )


@pytest.fixture
def example_decomp(
    caller_func: ExportedFunction,
    callee_func: ExportedFunction,
    imported_func: ExportedFunction,
) -> ExportedDecompilation:
    """:return: an ExportedDecompilation with caller, callee and an import."""
    return ExportedDecompilation(
        path=Path("/bin/example"),
        id=1,
        functions={
            0x1000: caller_func,
            0x2000: callee_func,
            0x3000: imported_func,
        },
    )


# ---------------------------------------------------------------------------
# ExportedLocation
# ---------------------------------------------------------------------------


class TestExportedLocation:
    """Tests for the ExportedLocation model."""

    def test_from_location(self) -> None:
        """from_location copies the four coordinates."""
        from pyrrha_mapper.mappers.decomp_mapper import Location

        loc = Location(start_line=3, start_col=4, end_line=3, end_col=10)
        exported = ExportedLocation.from_location(loc)
        assert exported.as_tuple() == (3, 4, 3, 10)

    def test_as_tuple(self, call_loc: ExportedLocation) -> None:
        """as_tuple returns the coordinates in declaration order."""
        assert call_loc.as_tuple() == (2, 3, 2, 6)

    def test_ordering(self) -> None:
        """Locations are ordered by their dumped tuple."""
        small = ExportedLocation(start_line=1, start_col=1, end_line=1, end_col=2)
        big = ExportedLocation(start_line=2, start_col=1, end_line=2, end_col=2)
        assert small < big
        assert small <= big
        assert big > small
        assert big >= small
        assert small <= small
        assert small >= small

    def test_roundtrip(self, call_loc: ExportedLocation) -> None:
        """A location survives a JSON round-trip."""
        reloaded = ExportedLocation.model_validate_json(call_loc.model_dump_json())
        assert reloaded == call_loc


# ---------------------------------------------------------------------------
# ExportedFunction
# ---------------------------------------------------------------------------


class TestExportedFunction:
    """Tests for the ExportedFunction model."""

    def test_property_delegation(self, caller_func: ExportedFunction) -> None:
        """id/name/demangled_name/addr delegate to the embedded symbol."""
        assert caller_func.id == 5
        assert caller_func.name == "foo"
        assert caller_func.demangled_name == "foo(int)"
        assert caller_func.addr == 0x1000

    def test_id_setter(self, caller_func: ExportedFunction) -> None:
        """Setting id updates the embedded symbol."""
        caller_func.id = 42
        assert caller_func.symbol.id == 42

    def test_repr(self, caller_func: ExportedFunction) -> None:
        """The repr uses the mangled name."""
        assert repr(caller_func) == "ExportedFunction('foo')"

    def test_non_func_symbol_rejected(self) -> None:
        """A symbol with is_func=False cannot back an ExportedFunction."""
        with pytest.raises(ValueError):
            ExportedFunction(
                symbol=Symbol(name="data", demangled_name="data", is_func=False, addr=1),
                type=FuncType.NORMAL,
            )

    def test_from_func_data(self) -> None:
        """from_func_data converts a mapper FuncData into an ExportedFunction."""
        from pyrrha_mapper.mappers.decomp_mapper import FuncData, Location

        symbol = Symbol(name="foo", demangled_name="foo", is_func=True, id=5, addr=0x1000)
        func = FuncData(
            symbol=symbol,
            type=FuncType.NORMAL,
            calls=[0x2000],
            callers=[0x500],
            source="void foo(){ bar(); }",
            source_id=9,
            declaration=Location(1, 6, 1, 9),
        )
        func.source_calls_loc[0x2000].append(Location(1, 13, 1, 16))

        exported = ExportedFunction.from_func_data(func)
        assert exported.name == "foo"
        assert exported.calls == [0x2000]
        assert exported.callers == [0x500]
        assert exported.source_id == 9
        assert exported.declaration is not None
        assert exported.declaration.as_tuple() == (1, 6, 1, 9)
        assert exported.source_calls_loc[0x2000][0].as_tuple() == (1, 13, 1, 16)

    def test_from_func_data_no_declaration(self, callee_symbol: Symbol) -> None:
        """from_func_data tolerates a missing declaration."""
        from pyrrha_mapper.mappers.decomp_mapper import FuncData

        func = FuncData(
            symbol=callee_symbol,
            type=FuncType.NORMAL,
            calls=[],
            callers=[],
            source="",
        )
        exported = ExportedFunction.from_func_data(func)
        assert exported.declaration is None
        assert exported.source_calls_loc == {}

    def test_roundtrip(self, caller_func: ExportedFunction) -> None:
        """An ExportedFunction survives a JSON round-trip."""
        reloaded = ExportedFunction.model_validate_json(caller_func.model_dump_json())
        assert reloaded == caller_func


# ---------------------------------------------------------------------------
# ExportedDecompilation
# ---------------------------------------------------------------------------


class TestExportedDecompilation:
    """Tests for the ExportedDecompilation model."""

    def test_name_from_path(self, example_decomp: ExportedDecompilation) -> None:
        """The name is derived from the path."""
        assert example_decomp.name == "example"

    def test_repr(self, example_decomp: ExportedDecompilation) -> None:
        """The repr reports the path and the function count."""
        assert repr(example_decomp) == "ExportedDecompilation('/bin/example', funcs=3)"

    def test_function_exists(self, example_decomp: ExportedDecompilation) -> None:
        """function_exists checks membership by address."""
        assert example_decomp.function_exists(0x1000)
        assert not example_decomp.function_exists(0xDEAD)

    def test_function_name_exists(self, example_decomp: ExportedDecompilation) -> None:
        """function_name_exists checks membership by mangled name."""
        assert example_decomp.function_name_exists("foo")
        assert not example_decomp.function_name_exists("missing")

    def test_get_function_by_addr(
        self, example_decomp: ExportedDecompilation, caller_func: ExportedFunction
    ) -> None:
        """get_function_by_addr retrieves the stored function."""
        assert example_decomp.get_function_by_addr(0x1000) == caller_func

    def test_get_function_by_name(
        self, example_decomp: ExportedDecompilation, caller_func: ExportedFunction
    ) -> None:
        """get_function_by_name retrieves by mangled name and raises otherwise."""
        assert example_decomp.get_function_by_name("foo") == caller_func
        with pytest.raises(KeyError):
            example_decomp.get_function_by_name("missing")

    def test_add_function(self, callee_func: ExportedFunction) -> None:
        """add_function stores a function under its address."""
        decomp = ExportedDecompilation(path=Path("/bin/x"))
        decomp.add_function(callee_func)
        assert decomp.function_exists(callee_func.addr)
        assert decomp.get_function_by_addr(callee_func.addr) == callee_func

    def test_iter_functions(self, example_decomp: ExportedDecompilation) -> None:
        """iter_functions yields every stored function."""
        names = sorted(f.name for f in example_decomp.iter_functions())
        assert names == ["bar", "foo", "puts"]

    def test_python_dump_keeps_int_keys(self, example_decomp: ExportedDecompilation) -> None:
        """A python-mode dump keeps integer address keys."""
        dump = example_decomp.model_dump()
        assert set(dump["functions"].keys()) == {0x1000, 0x2000, 0x3000}

    def test_json_dump_stringifies_keys(self, example_decomp: ExportedDecompilation) -> None:
        """A JSON-mode dump stringifies the integer address keys."""
        dump_json = json.loads(example_decomp.model_dump_json())
        assert set(dump_json["functions"].keys()) == {"4096", "8192", "12288"}

    def test_roundtrip_equal(self, example_decomp: ExportedDecompilation) -> None:
        """A full JSON round-trip preserves equality and int keys."""
        reloaded = ExportedDecompilation.model_validate_json(example_decomp.model_dump_json())
        assert reloaded == example_decomp
        assert set(reloaded.functions.keys()) == {0x1000, 0x2000, 0x3000}
        # nested int-keyed source_calls_loc is restored too
        assert reloaded.functions[0x1000].source_calls_loc[0x2000][0].as_tuple() == (2, 3, 2, 6)

    def test_write_and_from_json_export(
        self, example_decomp: ExportedDecompilation, tmp_path: Path
    ) -> None:
        """Calling write then from_json_export round-trips through a file."""
        export_path = tmp_path / "decomp.json"
        example_decomp.write(export_path)
        assert json.loads(export_path.read_text()), "exported data cannot be loaded as JSON"
        reloaded = ExportedDecompilation.from_json_export(export_path)
        assert reloaded == example_decomp

    def test_from_json_export_accepts_str_path(
        self, example_decomp: ExportedDecompilation, tmp_path: Path
    ) -> None:
        """from_json_export also accepts a plain string path."""
        export_path = tmp_path / "decomp.json"
        example_decomp.write(export_path)
        reloaded = ExportedDecompilation.from_json_export(str(export_path))
        assert reloaded == example_decomp

    def test_validate_rejects_non_dict_functions(self) -> None:
        """A non-dict functions payload is rejected."""
        with pytest.raises(ValueError):
            ExportedDecompilation.model_validate({"path": "/bin/x", "functions": "nope"})

    def test_validate_rejects_non_int_key(self, example_decomp: ExportedDecompilation) -> None:
        """A function key that cannot be coerced to int is rejected."""
        dump = json.loads(example_decomp.model_dump_json())
        dump["functions"]["not_an_int"] = dump["functions"].pop("4096")
        with pytest.raises(ValueError):
            ExportedDecompilation.model_validate(dump)

    def test_validate_rejects_addr_key_mismatch(self, caller_func: ExportedFunction) -> None:
        """A function stored under a key different from its symbol addr is rejected."""
        with pytest.raises(ValueError):
            ExportedDecompilation(path=Path("/bin/x"), functions={0x9999: caller_func})

    def test_from_mapper(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """from_mapper projects a DecompilMapper's bin and functions."""
        from pyrrha_mapper.mappers.decomp_mapper import FuncData
        from pyrrha_mapper.mappers.objects import Binary

        symbol = Symbol(name="foo", demangled_name="foo", is_func=True, id=5, addr=0x1000)

        class _FakeMapper:
            def __init__(self) -> None:
                self.bin = Binary(path=Path("/bin/example"), id=1)
                self.functions = {
                    0x1000: FuncData(
                        symbol=symbol,
                        type=FuncType.NORMAL,
                        calls=[],
                        callers=[],
                        source="void foo(){}",
                    )
                }

        export = ExportedDecompilation.from_mapper(_FakeMapper())  # type: ignore[arg-type]
        assert export.path == Path("/bin/example")
        assert export.id == 1
        assert export.name == "example"
        assert export.get_function_by_addr(0x1000).name == "foo"
