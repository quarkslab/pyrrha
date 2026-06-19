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
"""Backend-free unit tests for :class:`FileSystemImportsMapper`.

These tests exercise the DB-recording and resolution logic of the imports
mapper without disassembling anything. Two modes are used:

* ``db=None`` puts the mapper in *dry-run* mode, where the record_* methods
  early-return; this is used to test the FileSystem-only resolution logic.
* a :class:`FakeDB` recording every call drives the DB-writing branches.

The FileSystem / Binary / Symbol / Symlink objects are real (they are fully
covered elsewhere) so the resolution heuristics run against genuine data.
"""

from pathlib import Path

import pytest
from numbat.exceptions import DBException

from pyrrha_mapper.exceptions import PyrrhaError
from pyrrha_mapper.mappers.imports_mapper import FileSystemImportsMapper
from pyrrha_mapper.mappers.objects import Binary, FileSystem, Symbol, Symlink
from pyrrha_mapper.types import ResolveDuplicateOption

# --------------------------------------------------------------------------- #
#  Fake numbat DB
# --------------------------------------------------------------------------- #


class FakeDB:
    """Records every call; ids are incrementing so None-checks pass."""

    def __init__(self) -> None:
        self._next_id = 1
        self.node_types: list[tuple] = []
        self.classes: list[dict] = []
        self.methods: list[dict] = []
        self.fields: list[dict] = []
        self.typedefs: list[dict] = []
        self.ref_imports: list[tuple[int, int]] = []
        self.public_access: list[int] = []
        self.private_access: list[int] = []
        self.colors: list[int] = []
        self.committed = False
        # Toggles to drive failure / exception branches.
        self.fail_record_class = False
        self.fail_record_method = False
        self.fail_record_field = False
        self.raise_on_public_access = False
        self.raise_on_private_access = False

    def _alloc(self) -> int:
        val = self._next_id
        self._next_id += 1
        return val

    def set_node_type(self, type_to_change, graph_display=None, hover_display=None):  # noqa: D102
        self.node_types.append((type_to_change, graph_display, hover_display))

    def record_class(self, name, prefix="", delimiter=":", is_indexed=True):  # noqa: D102
        if self.fail_record_class:
            return None
        self.classes.append({"name": name, "prefix": prefix, "is_indexed": is_indexed})
        return self._alloc()

    def record_method(self, name, parent_id=None, prefix=""):  # noqa: D102
        if self.fail_record_method:
            return None
        self.methods.append({"name": name, "parent_id": parent_id, "prefix": prefix})
        return self._alloc()

    def record_field(self, name, parent_id=None, prefix="", is_indexed=True):  # noqa: D102
        if self.fail_record_field:
            return None
        self.fields.append({"name": name, "parent_id": parent_id, "is_indexed": is_indexed})
        return self._alloc()

    def record_typedef_node(self, name, prefix="", delimiter=":"):  # noqa: D102
        self.typedefs.append({"name": name, "prefix": prefix})
        return self._alloc()

    def record_ref_import(self, source_id, dest_id):  # noqa: D102
        self.ref_imports.append((source_id, dest_id))
        return self._alloc()

    def record_public_access(self, symbol_id):  # noqa: D102
        if self.raise_on_public_access:
            raise DBException("public access failed")
        self.public_access.append(symbol_id)

    def record_private_access(self, symbol_id):  # noqa: D102
        if self.raise_on_private_access:
            raise DBException("private access failed")
        self.private_access.append(symbol_id)

    def change_node_color(self, node_id, fill_color="", border_color=""):  # noqa: D102
        self.colors.append(node_id)

    def commit(self):  # noqa: D102
        self.committed = True


# --------------------------------------------------------------------------- #
#  Builders
# --------------------------------------------------------------------------- #


def make_dry_mapper(fs: FileSystem | None = None) -> FileSystemImportsMapper:
    """Build a dry-run mapper (db=None) optionally with a prebuilt FileSystem."""
    mapper = FileSystemImportsMapper(Path("/tmp"), None)
    if fs is not None:
        mapper.fs = fs
    return mapper


def make_db_mapper(fs: FileSystem | None = None) -> tuple[FileSystemImportsMapper, FakeDB]:
    """Build a mapper backed by a FakeDB (not dry-run)."""
    db = FakeDB()
    mapper = FileSystemImportsMapper(Path("/tmp"), db)
    if fs is not None:
        mapper.fs = fs
    return mapper, db


def make_binary(path: str, **kwargs) -> Binary:
    """Build a Binary at a given path."""
    return Binary(path=Path(path), **kwargs)


# --------------------------------------------------------------------------- #
#  __init__ / dry_run_mode
# --------------------------------------------------------------------------- #


class TestInitAndDryRun:
    """Tests for construction and the dry_run_mode flag."""

    def test_dry_run_when_no_db(self) -> None:
        """A mapper built without a db is in dry-run mode."""
        mapper = FileSystemImportsMapper(Path("/tmp"), None)
        assert mapper.dry_run_mode is True

    def test_db_mode_registers_node_types(self) -> None:
        """A mapper built with a db registers the NumbatUI node types."""
        _, db = make_db_mapper()
        # Four node types are registered for the graph customisation.
        assert len(db.node_types) == 4
        assert ("class", "Binaries", "binary") in db.node_types

    def test_dry_run_setter(self) -> None:
        """The dry_run_mode setter toggles the flag."""
        _, db = make_db_mapper()
        mapper = FileSystemImportsMapper(Path("/tmp"), db)
        assert mapper.dry_run_mode is False
        mapper.dry_run_mode = True
        assert mapper.dry_run_mode is True


# --------------------------------------------------------------------------- #
#  is_binary_supported
# --------------------------------------------------------------------------- #


class TestIsBinarySupported:
    """Tests for the is_binary_supported static method."""

    def test_non_file_rejected(self, tmp_path: Path) -> None:
        """A directory is not a supported binary."""
        assert FileSystemImportsMapper.is_binary_supported(tmp_path) is False

    def test_plain_text_rejected(self, tmp_path: Path) -> None:
        """A regular non-ELF/PE file is not supported."""
        f = tmp_path / "note.txt"
        f.write_text("hello")
        assert FileSystemImportsMapper.is_binary_supported(f) is False

    def test_symlink_rejected(self, tmp_path: Path) -> None:
        """A symlink is rejected even if its target would be supported."""
        target = tmp_path / "target.txt"
        target.write_text("x")
        link = tmp_path / "link"
        link.symlink_to(target)
        assert FileSystemImportsMapper.is_binary_supported(link) is False


# --------------------------------------------------------------------------- #
#  record_import_in_db
# --------------------------------------------------------------------------- #


class TestRecordImportInDB:
    """Tests for record_import_in_db."""

    def test_dry_run_records_nothing(self) -> None:
        """In dry-run mode no import is recorded."""
        mapper = make_dry_mapper()
        # Dry-run returns without touching any (absent) db interface.
        mapper.record_import_in_db(1, 2)
        assert mapper.db_interface is None

    def test_records_when_both_ids_present(self) -> None:
        """A valid (src, dest) pair is recorded as a ref import."""
        mapper, db = make_db_mapper()
        mapper.record_import_in_db(1, 2)
        assert db.ref_imports == [(1, 2)]

    def test_missing_id_logs_error(self, caplog) -> None:
        """A None id logs an error and records nothing."""
        mapper, db = make_db_mapper()
        with caplog.at_level("ERROR"):
            mapper.record_import_in_db(None, 2, "[t]")
        assert db.ref_imports == []
        assert any("Cannot record import" in r.message for r in caplog.records)


# --------------------------------------------------------------------------- #
#  record_binary_in_db
# --------------------------------------------------------------------------- #


class TestRecordBinaryInDB:
    """Tests for record_binary_in_db."""

    def test_dry_run_returns_binary_untouched(self) -> None:
        """In dry-run mode the binary is returned with no id assigned."""
        mapper = make_dry_mapper()
        b = make_binary("/bin/foo")
        assert mapper.record_binary_in_db(b) is b
        assert b.id is None

    def test_records_class_and_symbols(self) -> None:
        """Exported function/data and internal function are recorded."""
        mapper, db = make_db_mapper()
        b = make_binary("/bin/foo")
        b.add_exported_symbol(Symbol(name="ef", demangled_name="ef", is_func=True, addr=0x10))
        b.add_exported_symbol(
            Symbol(name="datag", demangled_name="datag", is_func=False, addr=0x20)
        )
        b.add_function(Symbol(name="intf", demangled_name="intf", is_func=True, addr=0x30))
        result = mapper.record_binary_in_db(b, "[t]")
        assert result.id is not None
        assert db.classes[0]["name"] == "foo"
        # Exported function recorded as method with a public access + color.
        assert any(m["name"] == "ef" for m in db.methods)
        assert db.public_access  # at least the exported symbol
        assert db.colors  # exported function got a colour
        # Exported data recorded as a field.
        assert any(f["name"] == "datag" for f in db.fields)
        # Internal function recorded as a method with private access.
        assert any(m["name"] == "intf" for m in db.methods)
        assert db.private_access

    def test_record_class_failure_returns_early(self) -> None:
        """When the class node cannot be recorded, no symbols are recorded."""
        mapper, db = make_db_mapper()
        db.fail_record_class = True
        b = make_binary("/bin/foo")
        b.add_exported_symbol(Symbol(name="ef", demangled_name="ef", is_func=True, addr=1))
        result = mapper.record_binary_in_db(b, "[t]")
        assert result.id is None
        assert db.methods == []

    def test_public_access_exception_wrapped(self) -> None:
        """A DBException on public access is wrapped in a PyrrhaError."""
        mapper, db = make_db_mapper()
        db.raise_on_public_access = True
        b = make_binary("/bin/foo")
        b.add_exported_symbol(Symbol(name="ef", demangled_name="ef", is_func=True, addr=1))
        with pytest.raises(PyrrhaError):
            mapper.record_binary_in_db(b, "[t]")

    def test_private_access_exception_wrapped(self) -> None:
        """A DBException on private access is wrapped in a PyrrhaError."""
        mapper, db = make_db_mapper()
        db.raise_on_private_access = True
        b = make_binary("/bin/foo")
        b.add_function(Symbol(name="intf", demangled_name="intf", is_func=True, addr=1))
        with pytest.raises(PyrrhaError):
            mapper.record_binary_in_db(b, "[t]")


# --------------------------------------------------------------------------- #
#  record_symlink_in_db
# --------------------------------------------------------------------------- #


class TestRecordSymlinkInDB:
    """Tests for record_symlink_in_db."""

    def test_dry_run_untouched(self) -> None:
        """In dry-run mode the symlink keeps its id (None)."""
        mapper = make_dry_mapper()
        target = make_binary("/bin/target", id=5)
        sym = Symlink(path=Path("/bin/link"), target=target)
        assert mapper.record_symlink_in_db(sym) is sym
        assert sym.id is None

    def test_records_typedef_and_import(self) -> None:
        """A symlink is recorded as a typedef and links to its target."""
        mapper, db = make_db_mapper()
        target = make_binary("/bin/target", id=5)
        sym = Symlink(path=Path("/bin/link"), target=target)
        mapper.record_symlink_in_db(sym, "[t]")
        assert sym.id is not None
        assert db.typedefs[0]["name"] == "link"
        # The import from symlink id to target id (5) is recorded.
        assert db.ref_imports == [(sym.id, 5)]


# --------------------------------------------------------------------------- #
#  _select_fs_component
# --------------------------------------------------------------------------- #


class TestSelectFsComponent:
    """Tests for the _select_fs_component selection strategy helper."""

    def test_single_match_returned_for_arbitrary(self) -> None:
        """A single candidate is returned regardless of strategy."""
        b = make_binary("/bin/foo")
        out = FileSystemImportsMapper._select_fs_component(
            ResolveDuplicateOption.ARBITRARY, [b], "[t]", "foo"
        )
        assert out is b

    def test_multiple_ignore_returns_none(self, caplog) -> None:
        """With several matches and IGNORE strategy, nothing is selected."""
        bins = [make_binary("/a/foo"), make_binary("/b/foo")]
        with caplog.at_level("DEBUG"):
            out = FileSystemImportsMapper._select_fs_component(
                ResolveDuplicateOption.IGNORE, bins, "[t]", "foo"
            )
        assert out is None

    def test_multiple_arbitrary_returns_first(self) -> None:
        """With ARBITRARY the first candidate is selected."""
        bins = [make_binary("/a/foo"), make_binary("/b/foo")]
        out = FileSystemImportsMapper._select_fs_component(
            ResolveDuplicateOption.ARBITRARY, bins, "[t]", "foo"
        )
        assert out is bins[0]

    def test_interactive_uses_cache(self, caplog) -> None:
        """With INTERACTIVE and a cache hit, the cached entry is reused (no prompt)."""
        a = make_binary("/a/foo")
        b = make_binary("/b/foo")
        with caplog.at_level("DEBUG"):
            out = FileSystemImportsMapper._select_fs_component(
                ResolveDuplicateOption.INTERACTIVE, [a, b], "[t]", "foo", cache=[b]
            )
        assert out is b


# --------------------------------------------------------------------------- #
#  commit
# --------------------------------------------------------------------------- #


class TestCommit:
    """Tests for commit."""

    def test_dry_run_no_commit(self) -> None:
        """In dry-run mode commit does nothing (and does not error)."""
        mapper = make_dry_mapper()
        mapper.commit()  # no exception

    def test_db_mode_commits(self) -> None:
        """In db mode commit forwards to the db interface."""
        mapper, db = make_db_mapper()
        mapper.commit()
        assert db.committed is True


# --------------------------------------------------------------------------- #
#  _resolve_lib_import
# --------------------------------------------------------------------------- #


class TestResolveLibImport:
    """Tests for _resolve_lib_import."""

    def _fs_with(self, **kwargs) -> FileSystem:
        return FileSystem(root_dir=Path("/tmp/foo"), **kwargs)

    def test_resolves_to_binary(self) -> None:
        """A library name matching a binary resolves to that binary."""
        lib = make_binary("/lib/libc.so", id=1)
        fs = self._fs_with(binaries={lib.path: lib})
        mapper = make_dry_mapper(fs)
        res = mapper._resolve_lib_import("libc.so", ResolveDuplicateOption.IGNORE, "[t]")
        assert isinstance(res, mapper._SolvedLibImport)
        assert res.final_import is lib

    def test_ambiguous_binary_ignore_fails(self) -> None:
        """Several matching binaries with IGNORE yields a failed import."""
        a = make_binary("/a/libc.so", id=1)
        b = make_binary("/b/libc.so", id=2)
        fs = self._fs_with(binaries={a.path: a, b.path: b})
        mapper = make_dry_mapper(fs)
        res = mapper._resolve_lib_import("libc.so", ResolveDuplicateOption.IGNORE, "[t]")
        assert isinstance(res, mapper._FailedLibImport)

    def test_resolves_through_symlink(self) -> None:
        """A name matching a symlink resolves to the symlink's target."""
        target = make_binary("/lib/libc-2.so", id=1)
        sym = Symlink(path=Path("/lib/libc.so"), target=target)
        fs = self._fs_with(binaries={target.path: target}, symlinks={sym.path: sym})
        mapper = make_dry_mapper(fs)
        res = mapper._resolve_lib_import("libc.so", ResolveDuplicateOption.ARBITRARY, "[t]")
        assert isinstance(res, mapper._SolvedLibImport)
        assert res.final_import is target

    def test_resolves_by_soname(self) -> None:
        """A name matching a binary SONAME (not its filename) resolves to it."""
        lib = make_binary("/lib/libpthread-2.11.so", id=1, soname="libpthread.so.0")
        fs = self._fs_with(binaries={lib.path: lib})
        mapper = make_dry_mapper(fs)
        res = mapper._resolve_lib_import("libpthread.so.0", ResolveDuplicateOption.ARBITRARY, "[t]")
        assert isinstance(res, mapper._SolvedLibImport)
        assert res.final_import is lib

    def test_unknown_lib_failed(self) -> None:
        """An unknown library name yields a failed import."""
        mapper = make_dry_mapper(self._fs_with())
        res = mapper._resolve_lib_import("missing.so", ResolveDuplicateOption.IGNORE, "[t]")
        assert isinstance(res, mapper._FailedLibImport)


# --------------------------------------------------------------------------- #
#  resolve_symbol_import
# --------------------------------------------------------------------------- #


class TestResolveSymbolImport:
    """Tests for resolve_symbol_import."""

    def test_plain_symbol_resolved_from_imported_lib(self) -> None:
        """A non-versioned symbol is resolved from an already-imported library."""
        lib = make_binary("/lib/libc.so", id=1)
        exported = Symbol(name="malloc", demangled_name="malloc", is_func=True, addr=1)
        lib.add_exported_symbol(exported)
        consumer = make_binary("/bin/app", id=2)
        consumer.add_imported_library(lib)
        mapper = make_dry_mapper()
        res = mapper.resolve_symbol_import(consumer, "malloc", ResolveDuplicateOption.IGNORE, "[t]")
        assert res is not None
        found_lib, found_sym = res
        assert found_lib is lib
        assert found_sym.name == "malloc"

    def test_plain_symbol_unresolved_returns_none(self) -> None:
        """A symbol not exported by any imported library is unresolved."""
        lib = make_binary("/lib/libc.so", id=1)
        consumer = make_binary("/bin/app", id=2)
        consumer.add_imported_library(lib)
        mapper = make_dry_mapper()
        res = mapper.resolve_symbol_import(consumer, "nope", ResolveDuplicateOption.IGNORE, "[t]")
        assert res is None

    def test_versioned_symbol_resolved(self) -> None:
        """A versioned symbol is resolved via the version requirement table."""
        lib = make_binary("/lib/libc.so", id=1)
        lib.add_exported_symbol(
            Symbol(name="printf", demangled_name="printf", is_func=True, addr=1)
        )
        fs = FileSystem(root_dir=Path("/tmp/foo"), binaries={lib.path: lib})
        consumer = make_binary("/bin/app", id=2)
        consumer.version_requirement = {"GLIBC_2.0": ["libc.so"]}
        mapper = make_dry_mapper(fs)
        res = mapper.resolve_symbol_import(
            consumer, "printf@@GLIBC_2.0", ResolveDuplicateOption.ARBITRARY, "[t]"
        )
        assert res is not None
        found_lib, found_sym = res
        assert found_sym.name == "printf"


# --------------------------------------------------------------------------- #
#  _record_non_resolved_symbol_import
# --------------------------------------------------------------------------- #


class TestRecordNonResolvedSymbolImport:
    """Tests for _record_non_resolved_symbol_import."""

    def test_dry_run_only_updates_binary(self, caplog) -> None:
        """In dry-run mode the symbol is tracked on the binary but not in db."""
        mapper = make_dry_mapper()
        b = make_binary("/bin/app", id=2)
        with caplog.at_level("WARNING"):
            mapper._record_non_resolved_symbol_import(b, "ghost")
        assert "ghost" in b.imported_symbol_names
        assert any("cannot resolve ghost" in r.message for r in caplog.records)

    def test_db_mode_records_field_and_import(self) -> None:
        """In db mode an unindexed field and an import link are recorded."""
        mapper, db = make_db_mapper()
        b = make_binary("/bin/app", id=2)
        mapper._record_non_resolved_symbol_import(b, "ghost")
        assert db.fields and db.fields[0]["name"] == "ghost"
        assert db.fields[0]["is_indexed"] is False
        assert db.ref_imports  # link from binary to the new field


# --------------------------------------------------------------------------- #
#  validators / dispatch
# --------------------------------------------------------------------------- #


class TestValidators:
    """Tests for _is_list_str, _correct_map_result and _treat_bin_parsing_result."""

    @pytest.mark.parametrize(
        "value, expected",
        [
            (["a", "b"], True),
            ([], True),
            (["a", 1], False),
            ("not a list", False),
        ],
    )
    def test_is_list_str(self, value, expected) -> None:
        """_is_list_str only accepts a list of strings."""
        assert FileSystemImportsMapper._is_list_str(value) is expected

    def test_correct_map_result(self) -> None:
        """_correct_map_result accepts a (Binary, Any) tuple only."""
        mapper = make_dry_mapper()
        assert mapper._correct_map_result((make_binary("/x"), None)) is True
        assert mapper._correct_map_result(("notbin", None)) is False
        assert mapper._correct_map_result("error string") is False

    def test_treat_parsing_result_error_string(self, caplog) -> None:
        """A string result is treated as an error and logged."""
        mapper = make_dry_mapper()
        with caplog.at_level("ERROR"):
            mapper._treat_bin_parsing_result(Path("/bin/x"), "parse error")
        assert any("parse error" in r.message for r in caplog.records)

    def test_treat_parsing_result_bad_shape_warns(self, caplog) -> None:
        """An unexpected result shape is logged as a warning."""
        mapper = make_dry_mapper()
        with caplog.at_level("WARNING"):
            mapper._treat_bin_parsing_result(Path("/bin/x"), 12345)
        assert any("impossible to parse" in r.message for r in caplog.records)

    def test_treat_parsing_result_valid_maps(self, monkeypatch) -> None:
        """A valid (Binary, info) result is forwarded to map_binary."""
        mapper = make_dry_mapper()
        seen: list = []
        monkeypatch.setattr(mapper, "map_binary", lambda b, info=None: seen.append((b, info)))
        b = make_binary("/bin/x")
        mapper._treat_bin_parsing_result(Path("/bin/x"), (b, "meta"))
        assert seen == [(b, "meta")]
