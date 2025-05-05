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
"""Unit test for FS objects. Pydantic classes are not tested if not modified."""

import json
from pathlib import Path

import pytest

from pyrrha_mapper.common import Binary, FileSystem, Symbol, Symlink


@pytest.fixture
def empty_bin() -> Binary:
    """:return: an empty binary (no imports, no exports, only a path)"""
    return Binary(path=Path("/bin/test_empty"), id=0)


@pytest.fixture
def example_imp_symb() -> Symbol:
    """:return: the symbol used as imported symbol in example_bin"""
    return Symbol(name="exemple", is_func=False, id=1, demangled_name="exemple")


@pytest.fixture
def example_imp_lib(example_imp_symb) -> Binary:
    """:return: the binary used as imported lib in example_bin"""
    return Binary(
        id=3,
        path=Path("/lib/my_lib"),
        exported_symbols={example_imp_symb.name: example_imp_symb},
    )


@pytest.fixture
def example_imp_non_resolved_lib() -> Binary:
    """:return: the binary used of an non resolved imported lib in example_bin"""
    return Binary(path=Path("non_resolved_lib"))


@pytest.fixture
def example_imp_non_resolved_symb() -> Symbol:
    """:return: the binary used of an non resolved imported symbol in example_bin"""
    return Symbol(name="non_resolved_symb", demangled_name="non_resolved_symb")


@pytest.fixture
def example_exp_symb() -> Symbol:
    """:return: the symbol used as exported symbol in example_bin"""
    return Symbol(name="my_func", is_func=True, id=2, demangled_name="my_func")


@pytest.fixture
def example_bin(
    example_imp_lib,
    example_imp_symb,
    example_imp_non_resolved_symb,
    example_imp_non_resolved_lib,
    example_exp_symb,
) -> Binary:
    """:return: a binary for tests"""
    return Binary(
        id=9,
        path=Path("/bin/test_bin"),
        imported_libraries={
            example_imp_lib.name: example_imp_lib,
            example_imp_non_resolved_lib.name: None,
        },
        imported_symbols={
            example_imp_symb.name: example_imp_symb,
            example_imp_non_resolved_symb.name: None,
        },
        exported_symbols={example_exp_symb.name: example_exp_symb},
        functions={example_exp_symb.name: example_exp_symb}
    )


@pytest.fixture
def empty_fs():
    """:return: a FileSystem instance with no binaries or symlinks"""
    return FileSystem(root_dir=Path("/tmp/foo"))


@pytest.fixture
def example_sym(example_bin):
    """:return: a Symlink which points on the example binary"""
    return Symlink(
        id=10,
        path=Path("/bin/my_symlink"),
        target_path=example_bin.path,
        target_id=example_bin.id,
    )


@pytest.fixture
def example_fs(empty_bin, example_bin, example_sym, example_imp_lib):
    """:return: an FileSystem instance with two binaries and one symlink"""
    return FileSystem(
        root_dir=Path("/tmp/foo"),
        binaries={
            empty_bin.path: empty_bin,
            example_bin.path: example_bin,
            example_imp_lib.path: example_imp_lib,
        },
        symlinks={example_sym.path: example_sym},
    )


class TestBinary:
    """Unit tests for Binary class."""

    @pytest.mark.parametrize(
        "_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"]
    )
    def test_add_imported_library_name(self, _bin, request: pytest.FixtureRequest):
        """Check if the name is added correctly and can be retrieved."""
        _bin = request.getfixturevalue(_bin)
        lib_name = "test"
        initial_imports = list(_bin.iter_imported_libraries())
        expected_names = list(_bin.imported_library_names) + [lib_name]
        _bin.add_imported_library_name(lib_name)
        assert sorted(list(_bin.imported_library_names)) == sorted(expected_names), (
            "Lib name not added"
        )
        assert len(list(_bin.iter_imported_libraries())) == len(initial_imports), (
            "Adding a lib name should not add an imported lib"
        )

    @pytest.mark.parametrize(
        "_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"]
    )
    def test_add_imported_symbol_name(self, _bin, request: pytest.FixtureRequest):  # type: ignore
        """Check if the name is added correctly and can be retrieved."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        symbol_name = "test"
        initial_imports = list(_bin.iter_imported_symbols())
        expected_names = list(_bin.imported_symbol_names) + [symbol_name]
        _bin.add_imported_symbol_name(symbol_name)
        assert sorted(list(_bin.imported_symbol_names)) == sorted(expected_names), (
            "Symbol name not added"
        )
        assert len(list(_bin.iter_imported_libraries())) == len(initial_imports), (
            "Adding a symbol name should not add an imported symbol"
        )

    @pytest.mark.parametrize(
        "_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"]
    )
    def test_add_imported_library(
        self,
        _bin: Binary,  # type: ignore
        request: pytest.FixtureRequest,
    ):
        """Check if the symbol is added correctly and can be retrieved."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        imported_bin = Binary(path=Path("/bin/imported_bin"))
        expected_imports = list(_bin.iter_imported_libraries()) + [imported_bin]
        expected_names = list(_bin.imported_library_names) + [imported_bin.name]
        _bin.add_imported_library(imported_bin)
        assert sorted(list(_bin.iter_imported_libraries())) == sorted(
            expected_imports
        ), "Lib not added"
        assert sorted(_bin.imported_library_names) == sorted(expected_names), (
            "Lib name not added"
        )

    @pytest.mark.parametrize(
        "_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"]
    )
    def test_add_imported_symbol(
        self,
        _bin: Binary,  # type: ignore
        request: pytest.FixtureRequest,
    ):
        """Check if the symbol is added correctly and can be retrieved."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        imported_symbol = Symbol(name="imported_symb", demangled_name="imported symbol")
        expected_imports = list(_bin.iter_imported_symbols()) + [imported_symbol]
        expected__names = _bin.imported_symbol_names + [imported_symbol.name]
        _bin.add_imported_symbol(imported_symbol)
        assert sorted(list(_bin.iter_imported_symbols())) == sorted(expected_imports), (
            "Symbol not added"
        )
        assert sorted(_bin.imported_symbol_names) == sorted(expected__names), (
            "Symbol name not added"
        )

    @pytest.mark.parametrize(
        "_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"]
    )
    def test_add_non_resolved_imported_library(
        self,
        _bin: Binary,  # type: ignore
        request: pytest.FixtureRequest,
    ):
        """Check if the non resolved lib is added correctly and well flagged."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        lib_name = "test"
        initial_imports = list(_bin.iter_imported_libraries())
        expected_names = _bin.imported_library_names + [lib_name]
        _bin.add_non_resolved_imported_library(lib_name)
        assert sorted(_bin.imported_library_names) == sorted(expected_names), (
            "Lib name not added"
        )
        assert len(list(_bin.iter_imported_libraries())) == len(initial_imports), (
            "Adding a lib name should not add an imported lib"
        )

    @pytest.mark.parametrize(
        "_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"]
    )
    def test_add_non_resolved_imported_symbol(
        self,
        _bin: Binary,  # type: ignore
        request: pytest.FixtureRequest,
    ):
        """Check if the symbol is added correctly and well flagged."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        symbol_name = "test"
        initial_imports = list(_bin.iter_imported_symbols())
        expected_import_names = set(_bin.imported_symbol_names)
        expected_import_names.add(symbol_name)
        _bin.add_non_resolved_imported_symbol(symbol_name)
        assert set(_bin.imported_symbol_names) == expected_import_names, (
            "Symbol name not added"
        )
        assert len(list(_bin.iter_imported_libraries())) == len(initial_imports), (
            "Adding a symbol name should not add an imported symbol"
        )

    @pytest.mark.parametrize(
        "_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"]
    )
    def test_add_exported_symbol(
        self,
        _bin: Binary,  # type: ignore
        request: pytest.FixtureRequest,
    ):
        """Check if the symbol is added correctly and can be retrieved."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        symbol = Symbol(name="imported_symb", demangled_name="IMported symb")
        expected_imports = list(_bin.iter_exported_symbols()) + [symbol]
        _bin.add_exported_symbol(symbol)
        assert sorted(list(_bin.iter_exported_symbols())) == sorted(expected_imports), (
            "Symbol not added"
        )
        assert _bin.exported_symbol_exists(symbol.name), "Symbol not listed as existing"
        assert _bin.get_exported_symbol(symbol.name) == symbol, "Cannot get new symbol"

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [("empty_bin", False), ("example_bin", True)],
        ids=["Empty bin", "Example bin"],
    )
    def test_exported_symbol_exist(
        self,
        _bin: Binary,  # type: ignore
        expected: bool,
        example_exp_symb: Symbol,
        request: pytest.FixtureRequest,
    ):
        """Check if the method return the correct values when symbol exists not."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        assert _bin.exported_symbol_exists(example_exp_symb.name) == expected

    def test_get_exported_symbol(self, example_bin: Binary, example_exp_symb: Symbol):
        """Check if a symbol is an exported symbol in the bin and retrieve it."""
        assert (
            example_bin.get_exported_symbol(example_exp_symb.name) == example_exp_symb
        )

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [("empty_bin", []), ("example_bin", ["example_exp_symb"])],
        ids=["Empty bin", "Example bin"],
    )
    def test_iter_exported_symbol(
        self,
        _bin: Binary,  # type: ignore
        expected: list[Symbol],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all the exported symbol of the bin."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x) for x in expected]  # type: ignore
        assert sorted(list(_bin.iter_exported_symbols())) == sorted(expected)

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [("empty_bin", []), ("example_bin", ["example_imp_symb"])],
        ids=["Empty bin", "Example bin"],
    )
    def test_iter_imported_symbol(
        self,
        _bin: Binary,  # type: ignore
        expected: list[Symbol],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all the resolved imported symbol of the bin."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x) for x in expected]  # type: ignore
        assert sorted(_bin.iter_imported_symbols()) == sorted(expected)

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [
            ("empty_bin", []),
            ("example_bin", ["example_imp_lib"]),
        ],
        ids=["Empty bin", "Example bin"],
    )
    def test_iter_imported_libraries(
        self,
        _bin: Binary,  # type: ignore
        expected: list[str],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all the resolved imported symbol of the bin."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x) for x in expected]  # type: ignore
        assert sorted(_bin.iter_imported_libraries()) == sorted(expected)

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [
            ("empty_bin", []),
            ("example_bin", ["example_imp_symb", "example_imp_non_resolved_symb"]),
        ],
        ids=["Empty bin", "Example bin"],
    )
    def test_iter_imported_symbol_names(
        self,
        _bin: Binary,  # type: ignore
        expected: list[Symbol],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all imported symbol names of the bin."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x).name for x in expected]  # type: ignore
        assert _bin.imported_symbol_names == sorted(expected)

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [
            ("empty_bin", []),
            ("example_bin", ["example_imp_lib", "example_imp_non_resolved_lib"]),
        ],
        ids=["Empty bin", "Example bin"],
    )
    def test_imported_library_names(
        self,
        _bin: Binary,  # type: ignore
        expected: list[Symbol],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all the imported lib names of the bin."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x).name for x in expected]  # type: ignore
        assert sorted(_bin.imported_library_names) == sorted(expected)


class TestFileSystem:
    """Unit tests for FileSystem class."""

    @pytest.mark.parametrize(
        "fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"]
    )
    def test_json_export_format(
        self, fs: FileSystem, tmp_path: Path, request: pytest.FixtureRequest
    ):
        """Check if json export create a JSON file."""
        fs = request.getfixturevalue(fs)  # type: ignore
        export_path = tmp_path / "export.json"
        fs.write(export_path)
        assert export_path.exists(), "JSON export file not created"
        assert json.loads(export_path.read_text()), (
            "exported data cannot be loaded as JSON"
        )

    @pytest.mark.parametrize(
        "fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"]
    )
    def test_binaries_serializer_error_handling(
        self, fs: FileSystem, request: pytest.FixtureRequest
    ):
        """Check exception are raised correctly for malformed binaries field."""
        fs = request.getfixturevalue(fs)  # type: ignore
        path = Path("/tmp/broken_path")
        fs.binaries[path] = None  # type: ignore # done to the purpose of the test
        fs._binary_names[path.name] = list()
        with pytest.raises(ValueError):
            fs.model_dump()
            fs.model_dump_json()

    @pytest.mark.parametrize(
        "fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"]
    )
    def test_json_dump_and_load(
        self, fs: FileSystem, tmp_path, request: pytest.FixtureRequest
    ):
        """JSON dump then reload. Check if original and new are the same."""
        fs = request.getfixturevalue(fs)  # type: ignore
        dump = fs.model_dump_json()
        res = FileSystem.model_validate_json(dump)
        assert isinstance(res, FileSystem), "Loaded object not a FileSystem"
        assert res == fs, "Loaded class is different from the original"

    @pytest.mark.parametrize(
        "fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"]
    )
    def test_dump_and_load(
        self, fs: FileSystem, tmp_path, request: pytest.FixtureRequest
    ):
        """Dump then reload. Check if original and new are the same."""
        fs = request.getfixturevalue(fs)  # type: ignore
        dump = fs.model_dump()
        res = FileSystem.model_validate(dump)
        assert isinstance(res, FileSystem), "Loaded object not a FileSystem"
        assert res == fs, "Loaded class is different from the original"

    @pytest.mark.parametrize(
        "fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"]
    )
    def test_add_binary(self, fs: FileSystem, request: pytest.FixtureRequest):  # type: ignore
        """Add a binary and check it can be retrieved with FS methods."""
        fs = request.getfixturevalue(fs)  # type: ignore
        _bin = Binary(id=19, path=Path("/bin/my_second_bin"))
        expected_bins = list(fs.iter_binaries()) + [_bin]
        fs.add_binary(_bin)
        assert fs.binary_exists(_bin), "Bin does not exist"
        assert fs.binary_name_exists(_bin.name), "Bin name does not exist"
        assert fs.get_binary_by_path(_bin.path) == _bin, "Cannot get bon by path"
        assert fs.get_binaries_by_name(_bin.name) == [_bin], "Cannot get bin by name"
        assert sorted(list(fs.iter_binaries())) == sorted(expected_bins), (
            "List of binaries not correct"
        )

    @pytest.mark.parametrize(
        "fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"]
    )
    def test_add_symlink(
        self, fs: FileSystem, example_bin, request: pytest.FixtureRequest
    ):  # type: ignore
        """Add a symlink and check it can be retrieved with FS methods."""
        fs = request.getfixturevalue(fs)  # type: ignore
        sym = Symlink(
            id=19,
            path=Path("/bin/my_second_symlink"),
            target_path=example_bin.path,
            target_id=example_bin.id,
        )
        expected_symlinks = list(fs.iter_symlinks()) + [sym]
        fs.add_symlink(sym)
        assert fs.symlink_exists(sym), "Symlink does not exist"
        assert fs.symlink_name_exists(sym.name), "Symlink name does not exist"
        assert fs.get_symlink_by_path(sym.path) == sym, "Cannot get symlink by path"
        assert fs.get_symlinks_by_name(sym.name) == [sym], "Cannot get symlink by name"
        assert sorted(list(fs.iter_symlinks())) == sorted(expected_symlinks), (
            "List of symlinks not correct"
        )

    @pytest.mark.parametrize(
        ["fs", "expected"],
        [("empty_fs", False), ("example_fs", True)],
        ids=["Empty FS", "Example FS"],
    )
    def test_binary_exists(
        self, fs: FileSystem, expected, example_bin, request: pytest.FixtureRequest
    ):
        """Check if a binary is present in the FileSystem instance."""
        fs = request.getfixturevalue(fs)  # type: ignore
        assert fs.binary_exists(example_bin) == expected

    @pytest.mark.parametrize(
        ["fs", "expected"],
        [("empty_fs", False), ("example_fs", True)],
        ids=["Empty FS", "Example FS"],
    )
    def test_symlink_exists(
        self, fs: FileSystem, expected, example_sym, request: pytest.FixtureRequest
    ):
        """Check if a symlink is present in the FileSystem instance."""
        fs = request.getfixturevalue(fs)  # type: ignore
        assert fs.symlink_exists(example_sym) == expected

    @pytest.mark.parametrize(
        ["fs", "expected"],
        [("empty_fs", False), ("example_fs", True)],
        ids=["Empty FS", "Example FS"],
    )
    def test_binary_name_exists(
        self, fs: FileSystem, expected, example_bin, request: pytest.FixtureRequest
    ):
        """Check if a binary name is present in the FileSystem instance."""
        fs = request.getfixturevalue(fs)  # type: ignore
        assert fs.binary_name_exists(example_bin.name) == expected

    @pytest.mark.parametrize(
        ["fs", "expected"],
        [("empty_fs", False), ("example_fs", True)],
        ids=["Empty FS", "Example FS"],
    )
    def test_symlink_name_exists(
        self, fs: FileSystem, expected, example_sym, request: pytest.FixtureRequest
    ):
        """Check if a symlink name is present in the FileSystem instance."""
        fs = request.getfixturevalue(fs)  # type: ignore
        assert fs.symlink_name_exists(example_sym.name) == expected

    def test_get_binaries_by_name(self, example_fs: FileSystem, example_bin):
        """Check if a binary of the FS can be get by its name."""
        assert example_fs.get_binaries_by_name(example_bin.name) == [example_bin]

    def test_get_binary_by_path(self, example_fs: FileSystem, example_bin):
        """Check if a binary of the FS can be get by its path."""
        assert example_fs.get_binary_by_path(example_bin.path) == example_bin

    def test_get_symlinks_by_name(self, example_fs: FileSystem, example_sym):
        """Check if a symlink of the FS can be get by its name."""
        assert example_fs.get_symlinks_by_name(example_sym.name) == [example_sym]

    def test_get_symlink_by_path(self, example_fs: FileSystem, example_sym):
        """Check if a symlink of the FS can be get by its path."""
        assert example_fs.get_symlink_by_path(example_sym.path) == example_sym

    def test_resolve_symlink(
        self, example_fs: FileSystem, example_bin: Binary, example_sym: Symlink
    ):
        """Check if example sym points well on example bin."""
        assert example_fs.resolve_symlink(example_sym) == example_bin

    def test_resolve_recursive_symlink(
        self, example_fs: FileSystem, example_bin: Binary, example_sym: Symlink
    ):
        """Check recursive symlink good resolution."""
        rec_sym = Symlink(
            id=29,
            path=Path("/tmp/rec_symlink"),
            target_path=example_sym.path,
            target_id=example_sym.id, # type: ignore
        )
        example_fs.add_symlink(rec_sym)
        assert example_fs.resolve_symlink(rec_sym) == example_bin

    def test_resolve_none_symlink(
        self, example_fs: FileSystem, example_bin: Binary, example_sym: Symlink
    ):
        """Check symlink which point on a non existing binary resolution."""
        rec_sym = Symlink(
            id=29,
            path=Path("/tmp/rec_symlink"),
            target_path=Path("/tmp/my_non_existing_binary_wow"),
            target_id=-1000,
        )
        example_fs.add_symlink(rec_sym)
        assert example_fs.resolve_symlink(rec_sym) is None
