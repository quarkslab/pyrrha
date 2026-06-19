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
"""Unit tests for the backend-agnostic logic of :class:`DecompilMapper`.

These tests exercise the recording, source-indexing and call-graph logic
without a disassembler backend. A :class:`DecompilMapper` instance is built
with ``object.__new__`` so ``Backend.__init__`` (which would open IDA or
Ghidra) is bypassed, and the numbat database is replaced by :class:`FakeDB`,
which records every call so the assertions can inspect what was sent to it.
"""

from collections import defaultdict
from pathlib import Path

import pytest

from pyrrha_mapper.mappers.decomp_mapper import (
    DecompilMapper,
    FuncData,
    Location,
    normalize_name,
)
from pyrrha_mapper.mappers.objects import Binary, Symbol
from pyrrha_mapper.types import FuncType


class FakeDB:
    """Minimal stand-in for ``numbat.SourcetrailDB`` recording every call.

    Each ``record_*`` method returns an incrementing id (so ``None`` checks in
    the mapper pass) and stores its arguments for inspection. ids can be forced
    to ``None`` to drive the error branches.
    """

    def __init__(self) -> None:
        self._next_id = 1
        self.files: list[tuple[Path, str]] = []
        self.file_languages: list[tuple[int, str]] = []
        self.functions: list[dict] = []
        self.classes: list[dict] = []
        self.symbol_locations: list[tuple] = []
        self.ref_calls: list[tuple[int, int]] = []
        self.reference_locations: list[tuple] = []
        self.node_types: list[tuple] = []
        # When set, the matching record_* returns None to drive error paths.
        self.fail_record_function = False
        self.fail_record_file = False
        self.fail_record_class = False
        self.fail_record_ref_call = False

    def _alloc(self) -> int:
        val = self._next_id
        self._next_id += 1
        return val

    def set_node_type(self, type_to_change, graph_display=None, hover_display=None):  # noqa: D102
        self.node_types.append((type_to_change, graph_display, hover_display))

    def record_class(self, name, prefix="", delimiter=":"):  # noqa: D102
        if self.fail_record_class:
            return None
        self.classes.append({"name": name, "prefix": prefix})
        return self._alloc()

    def record_function(self, name, prefix="", parent_id=None, **kwargs):  # noqa: D102
        if self.fail_record_function:
            return None
        self.functions.append({"name": name, "prefix": prefix, "parent_id": parent_id})
        return self._alloc()

    def record_file(self, path, name="", **kwargs):  # noqa: D102
        if self.fail_record_file:
            return None
        self.files.append((path, name))
        return self._alloc()

    def record_file_language(self, file_id, language):  # noqa: D102
        self.file_languages.append((file_id, language))

    def record_symbol_location(self, symbol_id, file_id, *loc):  # noqa: D102
        self.symbol_locations.append((symbol_id, file_id, *loc))
        return self._alloc()

    def record_ref_call(self, source_id, dest_id, hover_display=""):  # noqa: D102
        if self.fail_record_ref_call:
            return None
        self.ref_calls.append((source_id, dest_id))
        return self._alloc()

    def record_reference_location(self, reference_id, file_id, *loc):  # noqa: D102
        self.reference_locations.append((reference_id, file_id, *loc))
        return self._alloc()


class _FakeMapper(DecompilMapper):
    """Concrete DecompilMapper with the abstract backend methods stubbed.

    The backend accessors are not exercised by these tests (the function data
    is injected directly), so they raise if called by mistake.
    """

    def func_addrs(self):  # noqa: D102
        raise NotImplementedError

    def func_children(self, addr):  # noqa: D102
        raise NotImplementedError

    def func_parents(self, addr):  # noqa: D102
        raise NotImplementedError

    def func_type(self, addr):  # noqa: D102
        raise NotImplementedError

    def func_mangled_name(self, addr):  # noqa: D102
        raise NotImplementedError

    def func_demangled_name(self, addr):  # noqa: D102
        raise NotImplementedError

    def func_decompiled(self, addr):  # noqa: D102
        raise NotImplementedError

    def is_func_start(self, addr):  # noqa: D102
        raise NotImplementedError

    def close(self):  # noqa: D102
        pass


def make_mapper(db: FakeDB) -> DecompilMapper:
    """Build a DecompilMapper without running Backend.__init__ (no disassembler)."""
    mapper = object.__new__(_FakeMapper)
    mapper.db_interface = db
    mapper.bin = Binary(path=Path("/bin/test"))
    mapper.bin.id = 1
    mapper.functions = {}
    mapper.source_ids = {}
    return mapper


def make_func(
    addr: int,
    name: str,
    *,
    func_type: FuncType = FuncType.NORMAL,
    demangled: str | None = None,
    calls: list[int] | None = None,
    callers: list[int] | None = None,
    source: str = "",
    id: int | None = None,
) -> FuncData:
    """Build a FuncData with sensible defaults for tests."""
    func = FuncData(
        symbol=Symbol(
            name=name,
            demangled_name=demangled if demangled is not None else name,
            is_func=True,
            addr=addr,
            id=id,
        ),
        type=func_type,
        calls=calls if calls is not None else [],
        callers=callers if callers is not None else [],
        source=source,
    )
    func.source_calls_loc = defaultdict(list)
    return func


# --------------------------------------------------------------------------- #
#  normalize_name
# --------------------------------------------------------------------------- #


class TestNormalizeName:
    """Tests for the normalize_name helper."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("__memcpy", "memcpy"),
            ("memcpy", "memcpy"),
            (".hidden.", "hidden"),
            # strip("_") then strip(".") run once each, not repeatedly.
            ("_._mixed_._", "_mixed_"),
            ("", ""),
        ],
    )
    def test_strip(self, raw: str, expected: str) -> None:
        """Leading/trailing underscores and dots are stripped."""
        assert normalize_name(raw) == expected


# --------------------------------------------------------------------------- #
#  record_function
# --------------------------------------------------------------------------- #


class TestRecordFunction:
    """Tests for DecompilMapper.record_function."""

    def test_normal_function_recorded(self) -> None:
        """A normal function is recorded and receives an id."""
        db = FakeDB()
        mapper = make_mapper(db)
        func = make_func(0x1000, "foo", demangled="foo")
        result = mapper.record_function(func, "[test]")
        assert result.id is not None
        assert db.functions[0]["name"] == "foo"
        assert db.functions[0]["prefix"] == "0x1000"
        assert db.functions[0]["parent_id"] == mapper.bin.id

    def test_imported_function_skipped(self) -> None:
        """An imported function is not recorded and keeps a None id."""
        db = FakeDB()
        mapper = make_mapper(db)
        func = make_func(0x1000, "calloc", func_type=FuncType.IMPORTED)
        result = mapper.record_function(func, "[test]")
        assert result.id is None
        assert db.functions == []

    def test_record_failure_keeps_none_id(self) -> None:
        """When the DB returns None, the function id stays None."""
        db = FakeDB()
        db.fail_record_function = True
        mapper = make_mapper(db)
        func = make_func(0x1000, "foo")
        result = mapper.record_function(func, "[test]")
        assert result.id is None


# --------------------------------------------------------------------------- #
#  record_source
# --------------------------------------------------------------------------- #


class TestRecordSource:
    """Tests for DecompilMapper.record_source."""

    def test_records_file_and_declaration(self) -> None:
        """Source is recorded under a unique name and the declaration located."""
        db = FakeDB()
        mapper = make_mapper(db)
        func = make_func(0x1000, "foo", id=10, source="void foo(){}")
        func.declaration = Location(1, 6, 1, 9)
        result = mapper.record_source(func, "[test]")
        assert result.source_id is not None
        # File recorded under "<name>@<addr>" to guarantee uniqueness.
        assert db.files[0][1] == "foo@0x1000"
        assert db.file_languages[0][1] == "cpp"
        # The declaration was recorded as a symbol location.
        assert db.symbol_locations[0][0] == 10  # symbol id
        assert db.symbol_locations[0][2:] == (1, 6, 1, 9)

    def test_unique_name_per_address(self) -> None:
        """Two functions sharing a mangled name get distinct file names."""
        db = FakeDB()
        mapper = make_mapper(db)
        mapper.record_source(make_func(0x1000, "dup", id=1, source="a"), "[t]")
        mapper.record_source(make_func(0x2000, "dup", id=2, source="b"), "[t]")
        names = [name for _, name in db.files]
        assert names == ["dup@0x1000", "dup@0x2000"]
        assert len(set(names)) == 2

    def test_missing_declaration_warns(self, caplog) -> None:
        """A function without a located declaration logs a warning."""
        db = FakeDB()
        mapper = make_mapper(db)
        func = make_func(0x1000, "foo", id=10, source="void foo(){}")
        with caplog.at_level("WARNING"):
            mapper.record_source(func, "[test]")
        assert any("declaration not found" in r.message for r in caplog.records)
        assert db.symbol_locations == []

    def test_record_file_failure_returns_early(self) -> None:
        """When record_file returns None, no language/location is recorded."""
        db = FakeDB()
        db.fail_record_file = True
        mapper = make_mapper(db)
        func = make_func(0x1000, "foo", id=10, source="void foo(){}")
        func.declaration = Location(1, 6, 1, 9)
        result = mapper.record_source(func, "[test]")
        assert result.source_id is None
        assert db.file_languages == []
        assert db.symbol_locations == []

    def test_temporary_file_is_cleaned_up(self, monkeypatch) -> None:
        """The temporary source file is removed after recording."""
        db = FakeDB()
        mapper = make_mapper(db)
        captured: list[Path] = []

        original_record_file = db.record_file

        def spy(path, name="", **kwargs):
            captured.append(Path(path))
            return original_record_file(path, name=name, **kwargs)

        monkeypatch.setattr(db, "record_file", spy)
        func = make_func(0x1000, "foo", id=10, source="void foo(){}")
        mapper.record_source(func, "[test]")
        assert captured and not captured[0].exists()


# --------------------------------------------------------------------------- #
#  index_decompiled
# --------------------------------------------------------------------------- #


class TestIndexDecompiled:
    """Tests for DecompilMapper.index_decompiled."""

    def test_imported_function_skipped(self) -> None:
        """Imported functions are skipped entirely (no source recorded)."""
        db = FakeDB()
        mapper = make_mapper(db)
        func = make_func(0x1000, "calloc", func_type=FuncType.IMPORTED)
        mapper.functions = {0x1000: func}
        mapper.index_decompiled(0x1000, "[test]")
        assert db.files == []

    def test_declaration_and_callsites_located(self) -> None:
        """The declaration and each call site are located in the source."""
        db = FakeDB()
        mapper = make_mapper(db)
        callee = make_func(0x2000, "bar", id=20)
        caller_source = "void foo(void)\n{\n    bar();\n}"
        caller = make_func(0x1000, "foo", id=10, calls=[0x2000], source=caller_source)
        mapper.functions = {0x1000: caller, 0x2000: callee}
        mapper.index_decompiled(0x1000, "[test]")
        # Declaration located on the first line at column of "foo".
        assert caller.declaration is not None
        assert caller.declaration.start_line == 1
        # Call site to bar located on line 3.
        locs = caller.source_calls_loc[0x2000]
        assert len(locs) == 1
        assert locs[0].start_line == 3

    def test_suffix_match_is_skipped(self, caplog) -> None:
        """A callee whose name is a suffix of another is not double-counted."""
        db = FakeDB()
        mapper = make_mapper(db)
        # "stat" is a suffix of "lxstat"; only the longer match should win.
        lxstat = make_func(0x2000, "lxstat", id=20)
        stat = make_func(0x3000, "stat", id=30)
        src = "void foo(void)\n{\n    lxstat();\n}"
        caller = make_func(0x1000, "foo", id=10, calls=[0x2000, 0x3000], source=src)
        mapper.functions = {0x1000: caller, 0x2000: lxstat, 0x3000: stat}
        with caplog.at_level("DEBUG"):
            mapper.index_decompiled(0x1000, "[test]")
        # lxstat recorded, stat (suffix) not recorded as a separate call site.
        assert len(caller.source_calls_loc[0x2000]) == 1
        assert caller.source_calls_loc.get(0x3000, []) == []

    def test_missing_declaration_logs_error(self, caplog) -> None:
        """A source not containing the function name logs an error."""
        db = FakeDB()
        mapper = make_mapper(db)
        caller = make_func(0x1000, "foo", id=10, source="void something_else(void){}")
        mapper.functions = {0x1000: caller}
        with caplog.at_level("ERROR"):
            mapper.index_decompiled(0x1000, "[test]")
        assert any("declaration not found" in r.message for r in caplog.records)


# --------------------------------------------------------------------------- #
#  index_call_graph
# --------------------------------------------------------------------------- #


class TestIndexCallGraph:
    """Tests for DecompilMapper.index_call_graph."""

    def test_records_call_and_reference_location(self) -> None:
        """A call between two recorded functions is recorded with its location."""
        db = FakeDB()
        mapper = make_mapper(db)
        callee = make_func(0x2000, "bar", id=20)
        caller = make_func(0x1000, "foo", id=10, calls=[0x2000], source="void foo(){ bar(); }")
        caller.source_id = 99
        caller.source_calls_loc[0x2000].append(Location(1, 12, 1, 15))
        mapper.functions = {0x1000: caller, 0x2000: callee}
        mapper.index_call_graph(0x1000, "[test]")
        assert db.ref_calls == [(10, 20)]
        # The reference location uses the ref id (not the callee symbol id).
        assert len(db.reference_locations) == 1
        ref_id_used = db.reference_locations[0][0]
        assert ref_id_used not in (10, 20)  # it is the record_ref_call return

    def test_imported_caller_skipped(self) -> None:
        """An imported function is never a caller."""
        db = FakeDB()
        mapper = make_mapper(db)
        func = make_func(0x1000, "calloc", func_type=FuncType.IMPORTED, calls=[0x2000])
        mapper.functions = {0x1000: func}
        mapper.index_call_graph(0x1000, "[test]")
        assert db.ref_calls == []

    def test_unregistered_caller_skipped(self, caplog) -> None:
        """A caller without a DB id is skipped with a warning."""
        db = FakeDB()
        mapper = make_mapper(db)
        func = make_func(0x1000, "foo", id=None, calls=[0x2000])
        mapper.functions = {0x1000: func}
        with caplog.at_level("WARNING"):
            mapper.index_call_graph(0x1000, "[test]")
        assert db.ref_calls == []
        assert any("not a registered function" in r.message for r in caplog.records)

    def test_imported_callee_skipped_quietly(self, caplog) -> None:
        """A call to an imported callee is skipped without a warning."""
        db = FakeDB()
        mapper = make_mapper(db)
        callee = make_func(0x2000, "calloc", func_type=FuncType.IMPORTED, id=None)
        caller = make_func(0x1000, "foo", id=10, calls=[0x2000])
        mapper.functions = {0x1000: caller, 0x2000: callee}
        with caplog.at_level("WARNING"):
            mapper.index_call_graph(0x1000, "[test]")
        assert db.ref_calls == []
        assert not any("cannot record call" in r.message for r in caplog.records)

    def test_unknown_callee_addr_warns(self, caplog) -> None:
        """A call to an address with no known function logs a warning."""
        db = FakeDB()
        mapper = make_mapper(db)
        caller = make_func(0x1000, "foo", id=10, calls=[0x9999])
        mapper.functions = {0x1000: caller}
        with caplog.at_level("WARNING"):
            mapper.index_call_graph(0x1000, "[test]")
        assert db.ref_calls == []
        assert any("does not match a registered function" in r.message for r in caplog.records)

    def test_no_location_when_source_missing(self) -> None:
        """A recorded call with no source records no reference location."""
        db = FakeDB()
        mapper = make_mapper(db)
        callee = make_func(0x2000, "bar", id=20)
        caller = make_func(0x1000, "foo", id=10, calls=[0x2000], source="")
        mapper.functions = {0x1000: caller, 0x2000: callee}
        mapper.index_call_graph(0x1000, "[test]")
        assert db.ref_calls == [(10, 20)]
        assert db.reference_locations == []


# --------------------------------------------------------------------------- #
#  to_export
# --------------------------------------------------------------------------- #


class TestToExport:
    """Tests for DecompilMapper.to_export."""

    def test_export_projects_functions(self) -> None:
        """to_export projects every function into the export model."""
        db = FakeDB()
        mapper = make_mapper(db)
        foo = make_func(0x1000, "foo", id=10, calls=[0x2000], source="void foo(){}")
        bar = make_func(0x2000, "bar", id=20)
        mapper.functions = {0x1000: foo, 0x2000: bar}
        export = mapper.to_export()
        assert export.path == mapper.bin.path
        assert export.id == mapper.bin.id
        assert set(export.functions.keys()) == {0x1000, 0x2000}
        assert export.get_function_by_name("foo") is not None


# --------------------------------------------------------------------------- #
#  __init__ / index_function / map_binary
#
#  The tests above inject FuncData directly and build the mapper with
#  object.__new__, so the backend accessors, DecompilMapper.__init__ and the
#  map() orchestration are never exercised. The driver below provides
#  canned backend data so those paths run without a disassembler.
# --------------------------------------------------------------------------- #


class _DrivingMapper(DecompilMapper):
    """DecompilMapper whose backend accessors return canned in-memory data.

    A small fake "program" is described by ``_addrs`` (entry points) and
    ``_data`` (per-address name/type/calls/source). This lets ``__init__``,
    ``index_function`` and ``map_binary`` run end-to-end against a FakeDB.
    """

    def __init__(self, db: FakeDB, bin_path: Path, program: dict[int, dict]) -> None:
        self._program = program
        super().__init__(db, bin_path)

    @property
    def func_addrs(self):  # noqa: D102
        return iter(sorted(self._program))

    def func_children(self, addr):  # noqa: D102
        return list(self._program[addr].get("calls", []))

    def func_parents(self, addr):  # noqa: D102
        return list(self._program[addr].get("callers", []))

    def func_type(self, addr):  # noqa: D102
        return self._program[addr]["type"]

    def func_mangled_name(self, addr):  # noqa: D102
        return self._program[addr]["name"]

    def func_demangled_name(self, addr):  # noqa: D102
        return self._program[addr].get("demangled", self._program[addr]["name"])

    def func_decompiled(self, addr):  # noqa: D102
        return self._program[addr].get("source", "")

    def is_func_start(self, addr):  # noqa: D102
        return addr in self._program

    def close(self):  # noqa: D102
        pass


class TestInit:
    """Tests for DecompilMapper.__init__."""

    def test_sets_up_state_and_binary_group(self) -> None:
        """__init__ wires the db, an empty function map and the Binaries group."""
        db = FakeDB()
        mapper = _DrivingMapper(db, Path("/bin/sample"), {})
        assert mapper.db_interface is db
        assert mapper.functions == {}
        assert mapper.source_ids == {}
        assert mapper.bin.path == Path("/bin/sample")
        # A "Binaries" class node type is registered for NumbatUI grouping.
        assert ("class", "Binaries", "binary") in db.node_types


class TestIndexFunction:
    """Tests for DecompilMapper.index_function (drives the backend accessors)."""

    def test_indexes_normal_function(self) -> None:
        """A normal function is added to the binary and recorded with its data."""
        program = {
            0x1000: {
                "name": "foo",
                "demangled": "foo",
                "type": FuncType.NORMAL,
                "calls": [0x2000],
                "callers": [],
                "source": "void foo(void){ bar(); }",
            }
        }
        db = FakeDB()
        mapper = _DrivingMapper(db, Path("/bin/sample"), program)
        mapper.bin.id = 1
        mapper.index_function(0x1000, "[idx]")
        func = mapper.functions[0x1000]
        assert func.name == "foo"
        assert func.type == FuncType.NORMAL
        assert func.calls == [0x2000]
        assert func.source == "void foo(void){ bar(); }"
        assert func.id is not None
        assert mapper.bin.get_function_by_name("foo") is not None

    def test_imported_function_has_empty_source(self) -> None:
        """An imported function is indexed without querying decompiled source."""
        program = {
            0x3000: {
                "name": "calloc",
                "type": FuncType.IMPORTED,
                "source": "SHOULD NOT BE READ",
            }
        }
        db = FakeDB()
        mapper = _DrivingMapper(db, Path("/bin/sample"), program)
        mapper.bin.id = 1
        mapper.index_function(0x3000, "[idx]")
        assert mapper.functions[0x3000].source == ""


class TestMapBinary:
    """Tests for DecompilMapper.map() orchestration."""

    def test_full_run_records_binary_functions_and_calls(self) -> None:
        """map() records the binary node then indexes functions and calls."""
        program = {
            0x1000: {
                "name": "foo",
                "demangled": "foo",
                "type": FuncType.NORMAL,
                "calls": [0x2000],
                "callers": [],
                "source": "void foo(void)\n{\n    bar();\n}",
            },
            0x2000: {
                "name": "bar",
                "demangled": "bar",
                "type": FuncType.NORMAL,
                "calls": [],
                "callers": [0x1000],
                "source": "void bar(void)\n{\n}",
            },
        }
        db = FakeDB()
        mapper = _DrivingMapper(db, Path("/bin/sample"), program)
        assert mapper.map() is True
        # The binary was recorded as a class node.
        assert db.classes and db.classes[0]["name"] == "sample"
        # Both functions indexed and recorded.
        assert set(mapper.functions) == {0x1000, 0x2000}
        assert {f["name"] for f in db.functions} == {"foo", "bar"}
        # The foo -> bar call was recorded.
        assert db.ref_calls == [(mapper.functions[0x1000].id, mapper.functions[0x2000].id)]

    def test_binary_record_failure_aborts(self) -> None:
        """When the binary node cannot be recorded, map() returns False."""
        db = FakeDB()
        db.fail_record_class = True
        mapper = _DrivingMapper(
            db, Path("/bin/sample"), {0x1000: {"name": "foo", "type": FuncType.NORMAL}}
        )
        assert mapper.map() is False
        assert mapper.functions == {}
