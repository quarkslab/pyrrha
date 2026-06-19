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
"""Backend-free unit tests for :class:`InterImageCGMapper`.

These tests exercise the call-graph recording and resolution logic of the
inter-image mapper without disassembling anything. As in the imports-mapper
tests, ``db=None`` selects dry-run mode and a recording :class:`FakeDB` drives
the DB-writing branches. The FileSystem / Binary / Symbol objects are real.
"""

from pathlib import Path

from pyrrha_mapper.mappers.intercg_mapper import (
    IGNORE_LIST,
    InterImageCGMapper,
)
from pyrrha_mapper.mappers.objects import Binary, FileSystem, Symbol
from pyrrha_mapper.types import Backend, ResolveDuplicateOption

# --------------------------------------------------------------------------- #
#  Fake numbat DB
# --------------------------------------------------------------------------- #


class FakeDB:
    """Records the call-graph-relevant numbat operations."""

    def __init__(self) -> None:
        self._next_id = 1
        self.node_types: list[tuple] = []
        self.ref_calls: list[tuple[int, int]] = []
        self.functions: list[dict] = []
        self.classes: list[dict] = []
        self.methods: list[dict] = []
        self.fields: list[dict] = []

    def _alloc(self) -> int:
        val = self._next_id
        self._next_id += 1
        return val

    def set_node_type(self, type_to_change, graph_display=None, hover_display=None):  # noqa: D102
        self.node_types.append((type_to_change, graph_display, hover_display))

    def record_ref_call(self, source_id, dest_id, hover_display=""):  # noqa: D102
        self.ref_calls.append((source_id, dest_id))
        return self._alloc()

    def record_function(self, name, is_indexed=True, **kwargs):  # noqa: D102
        self.functions.append({"name": name, "is_indexed": is_indexed})
        return self._alloc()

    # --- methods used by FileSystemImportsMapper.record_binary_in_db --- #

    def record_class(self, name, prefix="", delimiter=":", is_indexed=True):  # noqa: D102
        self.classes.append({"name": name})
        return self._alloc()

    def record_method(self, name, parent_id=None, prefix=""):  # noqa: D102
        self.methods.append({"name": name})
        return self._alloc()

    def record_field(self, name, parent_id=None, prefix="", is_indexed=True):  # noqa: D102
        self.fields.append({"name": name})
        return self._alloc()

    def change_node_color(self, node_id, fill_color="", border_color=""):  # noqa: D102
        pass

    def record_public_access(self, symbol_id):  # noqa: D102
        pass

    def record_private_access(self, symbol_id):  # noqa: D102
        pass


# --------------------------------------------------------------------------- #
#  Builders
# --------------------------------------------------------------------------- #


def make_dry_mapper(fs: FileSystem | None = None) -> InterImageCGMapper:
    """Build a dry-run inter-image mapper (db=None)."""
    mapper = InterImageCGMapper(Path("/tmp"), None, Backend.IDA)
    if fs is not None:
        mapper.fs = fs
    return mapper


def make_db_mapper(fs: FileSystem | None = None) -> tuple[InterImageCGMapper, FakeDB]:
    """Build an inter-image mapper backed by a FakeDB."""
    db = FakeDB()
    mapper = InterImageCGMapper(Path("/tmp"), db, Backend.IDA)
    if fs is not None:
        mapper.fs = fs
    return mapper, db


def func(name: str, addr: int, *, id: int | None = None) -> Symbol:
    """Build a function Symbol."""
    return Symbol(name=name, demangled_name=name, is_func=True, addr=addr, id=id)


def make_binary(path: str, **kwargs) -> Binary:
    """Build a Binary at a path."""
    return Binary(path=Path(path), **kwargs)


# --------------------------------------------------------------------------- #
#  __init__ / _correct_map_result
# --------------------------------------------------------------------------- #


class TestInit:
    """Tests for construction."""

    def test_dry_run_state(self) -> None:
        """A db-less mapper is in dry-run mode with empty maps."""
        mapper = make_dry_mapper()
        assert mapper.dry_run_mode is True
        assert mapper.backend == Backend.IDA
        assert mapper.node_ids == {}
        assert mapper.exports_to_bins == {}
        assert mapper.unresolved_callgraph == {}

    def test_db_mode_registers_binaries_header(self) -> None:
        """In db mode the Binaries node type is registered."""
        _, db = make_db_mapper()
        assert ("class", "Binaries", "binary") in db.node_types


class TestCorrectMapResult:
    """Tests for the overridden _correct_map_result."""

    def test_accepts_binary_and_callgraph_dict(self) -> None:
        """A (Binary, dict[Symbol, list[str]]) tuple is accepted."""
        mapper = make_dry_mapper()
        b = make_binary("/x")
        cg = {func("f", 1): ["g", "h"]}
        assert mapper._correct_map_result((b, cg)) is True

    def test_rejects_non_str_call_list(self) -> None:
        """A call list containing non-strings is rejected."""
        mapper = make_dry_mapper()
        b = make_binary("/x")
        assert mapper._correct_map_result((b, {func("f", 1): [123]})) is False

    def test_rejects_non_dict_second_element(self) -> None:
        """A second element that is not a dict is rejected."""
        mapper = make_dry_mapper()
        b = make_binary("/x")
        assert mapper._correct_map_result((b, ["not", "a", "dict"])) is False


# --------------------------------------------------------------------------- #
#  load_binary_args
# --------------------------------------------------------------------------- #


class TestLoadBinaryArgs:
    """Tests for load_binary_args."""

    def test_includes_backend(self) -> None:
        """The backend is injected into the per-firmware load args."""
        mapper = make_dry_mapper()
        args = mapper.load_binary_args()
        assert args["backend"] == Backend.IDA


# --------------------------------------------------------------------------- #
#  map_binary
# --------------------------------------------------------------------------- #


class TestMapBinary:
    """Tests for the map_binary override."""

    def test_stores_unresolved_callgraph(self) -> None:
        """An additional call-graph result is stored under the binary path."""
        mapper = make_dry_mapper()
        b = make_binary("/bin/app")
        cg = {func("f", 1): ["g"]}
        mapper.map_binary(b, cg)
        assert mapper.unresolved_callgraph[b.path] == cg

    def test_registers_node_id_when_recorded(self) -> None:
        """A binary recorded in db is registered in node_ids by its id."""
        mapper, _ = make_db_mapper()
        b = make_binary("/bin/app")
        b.add_exported_symbol(func("exp", 0x10))
        mapper.map_binary(b, None)
        assert b.id is not None
        assert mapper.node_ids[b.id] is b


# --------------------------------------------------------------------------- #
#  _treat_bin_parsing_result
# --------------------------------------------------------------------------- #


class TestTreatBinParsingResult:
    """Tests for _treat_bin_parsing_result."""

    def test_error_string_logged(self, caplog) -> None:
        """A string result is logged as an error."""
        mapper = make_dry_mapper()
        with caplog.at_level("ERROR"):
            mapper._treat_bin_parsing_result(Path("/bin/x"), "load failed")
        assert any("load failed" in r.message for r in caplog.records)

    def test_exception_logged(self, caplog) -> None:
        """A BaseException result is logged as an error."""
        mapper = make_dry_mapper()
        with caplog.at_level("ERROR"):
            mapper._treat_bin_parsing_result(Path("/bin/x"), ValueError("boom"))
        assert any("boom" in r.message for r in caplog.records)

    def test_full_result_maps(self, monkeypatch) -> None:
        """A (Binary, callgraph) result is forwarded to map_binary."""
        mapper = make_dry_mapper()
        seen: list = []
        monkeypatch.setattr(mapper, "map_binary", lambda b, info=None: seen.append((b, info)))
        b = make_binary("/bin/x")
        cg = {func("f", 1): ["g"]}
        mapper._treat_bin_parsing_result(Path("/bin/x"), (b, cg))
        assert seen == [(b, cg)]

    def test_lief_fallback(self, monkeypatch, caplog) -> None:
        """A (Binary, None) result falls back to lief-only mapping with a log."""
        mapper = make_dry_mapper()
        seen: list = []
        monkeypatch.setattr(mapper, "map_binary", lambda b, info=None: seen.append((b, info)))
        b = make_binary("/bin/x")
        with caplog.at_level("INFO"):
            mapper._treat_bin_parsing_result(Path("/bin/x"), (b, None))
        assert seen == [(b, None)]
        assert any("fallback to lief" in r.message for r in caplog.records)


# --------------------------------------------------------------------------- #
#  _merge_parser_functions_into_cached_binary
# --------------------------------------------------------------------------- #


class TestMergeParserFunctions:
    """Tests for the static _merge_parser_functions_into_cached_binary helper."""

    def test_merges_missing_internal_function(self) -> None:
        """An internal function only in parser_bin is added to cached_bin."""
        parser = make_binary("/bin/app")
        parser.add_function(func("only_parser", 0x100))
        cached = make_binary("/bin/app")
        InterImageCGMapper._merge_parser_functions_into_cached_binary(parser, cached)
        assert cached.function_exists("only_parser")

    def test_merges_missing_exported_function(self) -> None:
        """An exported function only in parser_bin is added to cached_bin."""
        parser = make_binary("/bin/app")
        parser.add_exported_symbol(func("new_export", 0x200))
        cached = make_binary("/bin/app")
        InterImageCGMapper._merge_parser_functions_into_cached_binary(parser, cached)
        assert cached.exported_function_exists("new_export")

    def test_does_not_overwrite_existing(self) -> None:
        """A function already present in cached_bin is preserved (keeps its id)."""
        parser = make_binary("/bin/app")
        parser.add_function(func("shared", 0x100))
        cached = make_binary("/bin/app")
        cached.add_function(func("shared", 0x100, id=42))
        InterImageCGMapper._merge_parser_functions_into_cached_binary(parser, cached)
        assert cached.get_function_by_name("shared").id == 42


# --------------------------------------------------------------------------- #
#  _record_call_ref / _record_unindexed_call
# --------------------------------------------------------------------------- #


class TestRecordCallRef:
    """Tests for _record_call_ref."""

    def test_dry_run_returns_true(self) -> None:
        """In dry-run mode the call ref is considered recorded."""
        mapper = make_dry_mapper()
        assert mapper._record_call_ref(func("a", 1), func("b", 2)) is True

    def test_records_when_both_have_ids(self) -> None:
        """A call between two id-bearing symbols is recorded."""
        mapper, db = make_db_mapper()
        assert mapper._record_call_ref(func("a", 1, id=1), func("b", 2, id=2)) is True
        assert db.ref_calls == [(1, 2)]

    def test_missing_id_returns_false(self, caplog) -> None:
        """A missing id yields a logged error and a False result."""
        mapper, db = make_db_mapper()
        with caplog.at_level("ERROR"):
            res = mapper._record_call_ref(func("a", 1, id=1), func("b", 2, id=None))
        assert res is False
        assert db.ref_calls == []


class TestRecordUnindexedCall:
    """Tests for _record_unindexed_call."""

    def test_dry_run_records_nothing(self) -> None:
        """In dry-run mode nothing is recorded."""
        mapper = make_dry_mapper()
        assert mapper._record_unindexed_call(func("a", 1, id=1), "ghost") is None

    def test_records_unindexed_function_and_ref(self) -> None:
        """An unindexed function node and a call ref to it are recorded."""
        mapper, db = make_db_mapper()
        mapper._record_unindexed_call(func("a", 1, id=1), "ghost")
        assert db.functions and db.functions[0]["name"] == "ghost"
        assert db.functions[0]["is_indexed"] is False
        assert db.ref_calls and db.ref_calls[0][0] == 1

    def test_missing_src_id_logs_error(self, caplog) -> None:
        """When the source has no id, no call ref is recorded."""
        mapper, db = make_db_mapper()
        with caplog.at_level("ERROR"):
            mapper._record_unindexed_call(func("a", 1, id=None), "ghost")
        # The function node is still created, but no call ref is recorded.
        assert db.ref_calls == []


# --------------------------------------------------------------------------- #
#  _make_export_to_binaries_map
# --------------------------------------------------------------------------- #


class TestMakeExportToBinariesMap:
    """Tests for _make_export_to_binaries_map."""

    def test_groups_exporters_by_symbol(self) -> None:
        """Each exported function name maps to every binary exporting it."""
        a = make_binary("/bin/a")
        a.add_exported_symbol(func("shared", 0x10))
        a.add_exported_symbol(func("only_a", 0x20))
        b = make_binary("/bin/b")
        b.add_exported_symbol(func("shared", 0x30))
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={a.path: a, b.path: b})
        mapper = make_dry_mapper(fs)
        table = mapper._make_export_to_binaries_map()
        assert a in table["shared"] and b in table["shared"]
        assert len(table["shared"]) == 2
        assert table["only_a"] == [a]


# --------------------------------------------------------------------------- #
#  _record_one_call
# --------------------------------------------------------------------------- #


class TestRecordOneCall:
    """Tests for the call-resolution logic of _record_one_call."""

    def _mapper_with_exports(self, fs: FileSystem) -> InterImageCGMapper:
        mapper = make_dry_mapper(fs)
        mapper.exports_to_bins = mapper._make_export_to_binaries_map()
        return mapper

    def test_local_call_resolved(self) -> None:
        """A callee defined in the same binary is resolved locally."""
        b = make_binary("/bin/app")
        caller = func("caller", 0x10)
        callee = func("callee", 0x20)
        b.add_function(caller)
        b.add_function(callee)
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={b.path: b})
        mapper = self._mapper_with_exports(fs)
        out = mapper._record_one_call(b, caller, "callee", ResolveDuplicateOption.IGNORE, set())
        assert out is True

    def test_ignore_listed_callee_dropped(self) -> None:
        """A callee in the IGNORE_LIST is dropped without resolution."""
        b = make_binary("/bin/app")
        caller = func("caller", 0x10)
        b.add_function(caller)
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={b.path: b})
        mapper = self._mapper_with_exports(fs)
        ignored = next(iter(IGNORE_LIST))
        out = mapper._record_one_call(b, caller, ignored, ResolveDuplicateOption.IGNORE, set())
        assert out is False

    def test_ghidra_synthetic_callee_dropped(self) -> None:
        """A Ghidra synthetic name (FUN_*) is dropped."""
        b = make_binary("/bin/app")
        caller = func("caller", 0x10)
        b.add_function(caller)
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={b.path: b})
        mapper = self._mapper_with_exports(fs)
        out = mapper._record_one_call(
            b, caller, "FUN_00101234", ResolveDuplicateOption.IGNORE, set()
        )
        assert out is False

    def test_template_and_version_suffix_stripped(self) -> None:
        """Template args and @@version suffixes are stripped before lookup."""
        b = make_binary("/bin/app")
        caller = func("caller", 0x10)
        callee = func("insert", 0x20)
        b.add_function(caller)
        b.add_function(callee)
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={b.path: b})
        mapper = self._mapper_with_exports(fs)
        # "insert<bool>" -> "insert", "insert@@V" -> "insert"
        assert (
            mapper._record_one_call(b, caller, "insert<bool>", ResolveDuplicateOption.IGNORE, set())
            is True
        )
        assert (
            mapper._record_one_call(
                b, caller, "insert@@GLIBC_2.0", ResolveDuplicateOption.IGNORE, set()
            )
            is True
        )

    def test_resolved_via_single_exporter(self) -> None:
        """An unresolved callee exported by a single other binary is linked."""
        lib = make_binary("/lib/liba.so")
        lib.add_exported_symbol(func("exported_fn", 0x100))
        app = make_binary("/bin/app")
        caller = func("caller", 0x10)
        app.add_function(caller)
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={lib.path: lib, app.path: app})
        mapper = self._mapper_with_exports(fs)
        out = mapper._record_one_call(
            app, caller, "exported_fn", ResolveDuplicateOption.ARBITRARY, set()
        )
        assert out is True
        assert app.imported_library_exists(lib.name)

    def test_multiple_exporters_ignore_unresolved(self, caplog) -> None:
        """Several exporters with IGNORE leaves the edge unresolved (False)."""
        lib_a = make_binary("/lib/liba.so")
        lib_a.add_exported_symbol(func("dup", 0x100))
        lib_b = make_binary("/lib/libb.so")
        lib_b.add_exported_symbol(func("dup", 0x200))
        app = make_binary("/bin/app")
        caller = func("caller", 0x10)
        app.add_function(caller)
        fs = FileSystem(
            root_dir=Path("/tmp/foo"),
            binaries={lib_a.path: lib_a, lib_b.path: lib_b, app.path: app},
        )
        mapper = self._mapper_with_exports(fs)
        with caplog.at_level("WARNING"):
            out = mapper._record_one_call(app, caller, "dup", ResolveDuplicateOption.IGNORE, set())
        assert out is False

    def test_unresolved_callee_added_to_unindex(self, caplog) -> None:
        """A callee exported by nobody is recorded as unindexed and tracked."""
        app = make_binary("/bin/app")
        caller = func("caller", 0x10)
        app.add_function(caller)
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={app.path: app})
        mapper = self._mapper_with_exports(fs)
        unindex: set[str] = set()
        with caplog.at_level("WARNING"):
            out = mapper._record_one_call(
                app, caller, "nowhere", ResolveDuplicateOption.IGNORE, unindex
            )
        assert out is False
        assert "nowhere" in unindex

    def test_unresolved_callee_in_ko_not_tracked(self) -> None:
        """An unresolved callee in a .ko file is not added to unindex_symbols."""
        ko = make_binary("/lib/modules/mod.ko")
        caller = func("caller", 0x10)
        ko.add_function(caller)
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={ko.path: ko})
        mapper = self._mapper_with_exports(fs)
        unindex: set[str] = set()
        out = mapper._record_one_call(
            ko, caller, "kernel_api_call", ResolveDuplicateOption.IGNORE, unindex
        )
        assert out is False
        assert unindex == set()  # kernel API calls are not ELF imports
