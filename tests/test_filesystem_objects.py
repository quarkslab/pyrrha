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
from random import randint
from typing import NamedTuple, Self

import pytest

from pyrrha_mapper.common import Binary, FileSystem, Symbol, Symlink


class SerializedFS(NamedTuple):
    """NamedTuple which store both the classic dump and the json one of the same fs."""

    dump: dict
    json: str

    @classmethod
    def from_fs(cls, fs: FileSystem) -> Self:
        """:return: a SerializedFS generated from the given fs"""
        return cls(dump=fs.model_dump(), json=fs.model_dump_json())


@pytest.fixture
def empty_bin() -> Binary:
    """:return: an empty binary (no imports, no exports, only a path)"""
    return Binary(path=Path("/bin/test_empty"), id=0)


@pytest.fixture
def example_imp_symb() -> Symbol:
    """:return: the symbol used as imported symbol in example_bin"""
    return Symbol(name="exemple", is_func=False, id=1, demangled_name="exemple")


@pytest.fixture
def example_imp_func() -> Symbol:
    """:return: the symbol used as imported function in example_bin"""
    return Symbol(
        name="exemple_imp_func", is_func=True, id=12365, demangled_name="exemple_imp_func", addr=123
    )


@pytest.fixture
def example_imp_lib(example_imp_symb, example_imp_func) -> Binary:
    """:return: the binary used as imported lib in example_bin"""
    return Binary(
        id=3,
        path=Path("/lib/my_lib"),
        exported_symbols={example_imp_symb.name: example_imp_symb},
        exported_functions={example_imp_func.name: example_imp_func},
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
def example_exp_func() -> Symbol:
    """:return: the symbol used as exported func in example_bin"""
    return Symbol(name="my_func", is_func=True, id=2, demangled_name="my_func", addr=24)


@pytest.fixture
def example_int_func() -> Symbol:
    """:return: the symbol used as internal func in example_bin"""
    return Symbol(name="my_int_func", is_func=True, id=200, demangled_name="my_int_func", addr=25)


@pytest.fixture
def example_exp_symb() -> Symbol:
    """:return: the symbol used as exported symbol in example_bin"""
    return Symbol(name="my_symb_exp", is_func=False, id=20, demangled_name="my_symb_expo")


@pytest.fixture
def example_bin(
    example_imp_lib,
    example_imp_symb,
    example_imp_func,
    example_imp_non_resolved_symb,
    example_imp_non_resolved_lib,
    example_exp_symb,
    example_exp_func,
    example_int_func,
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
            example_imp_func.name: example_imp_func,
            example_imp_non_resolved_symb.name: None,
        },
        exported_symbols={example_exp_symb.name: example_exp_symb},
        exported_functions={example_exp_func.name: example_exp_func},
        internal_functions={example_int_func.name: example_int_func},
        calls={example_int_func.name: [example_imp_func]},
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
        target=example_bin,
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

    @pytest.mark.parametrize("_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
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

    @pytest.mark.parametrize("_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
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
        assert len(list(_bin.iter_imported_symbols())) == len(initial_imports), (
            "Adding a symbol name should not add an imported symbol"
        )

    @pytest.mark.parametrize("_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
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
        assert sorted(list(_bin.iter_imported_libraries())) == sorted(expected_imports), (
            "Lib not added"
        )
        assert sorted(_bin.imported_library_names) == sorted(expected_names), "Lib name not added"

    @pytest.mark.parametrize("_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
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

    @pytest.mark.parametrize("_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
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
        assert sorted(_bin.imported_library_names) == sorted(expected_names), "Lib name not added"
        assert len(list(_bin.iter_imported_libraries())) == len(initial_imports), (
            "Adding a lib name should not add an imported lib"
        )

    @pytest.mark.parametrize("_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
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
        assert set(_bin.imported_symbol_names) == expected_import_names, "Symbol name not added"
        assert len(list(_bin.iter_imported_symbols())) == len(initial_imports), (
            "Adding a symbol name should not add an imported symbol"
        )

    @pytest.mark.parametrize("_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
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

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [("empty_bin", False), ("example_bin", True)],
        ids=["Empty bin", "Example bin"],
    )
    def test_exported_function_exist(
        self,
        _bin: Binary,  # type: ignore
        expected: bool,
        example_exp_func: Symbol,
        request: pytest.FixtureRequest,
    ):
        """Check if the method return the correct values when function exists or not."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        assert _bin.exported_function_exists(example_exp_func.name) == expected

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [("empty_bin", False), ("example_bin", True)],
        ids=["Empty bin", "Example bin"],
    )
    def test_imported_lib_exist(
        self,
        _bin: Binary,  # type: ignore
        expected: bool,
        example_imp_lib: Binary,
        request: pytest.FixtureRequest,
    ):
        """Check if the method return the correct values when lib exists  or not."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        assert _bin.imported_library_exists(example_imp_lib.name) == expected

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [("empty_bin", False), ("example_bin", True)],
        ids=["Empty bin", "Example bin"],
    )
    def test_func_exist(
        self,
        _bin: Binary,  # type: ignore
        expected: bool,
        example_int_func: Symbol,
        request: pytest.FixtureRequest,
    ):
        """Check if the method return the correct values when the func exists or not."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        assert _bin.function_exists(example_int_func.name) == expected

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [("empty_bin", False), ("example_bin", True)],
        ids=["Empty bin", "Example bin"],
    )
    def test_imported_symbol_exist(
        self,
        _bin: Binary,  # type: ignore
        expected: bool,
        example_imp_symb: Symbol,
        request: pytest.FixtureRequest,
    ):
        """Check if the method return the correct values when symbol exists not."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        assert _bin.imported_symbol_exists(example_imp_symb.name) == expected

    @pytest.mark.parametrize(
        "exp_symb", ["example_exp_symb", "example_exp_func"], ids=["Symbol", "Function"]
    )
    def test_get_exported_symbol(
        self,
        example_bin: Binary,
        empty_bin: Binary,
        exp_symb: Symbol,  # type: ignore
        request: pytest.FixtureRequest,
    ):
        """Check if a symbol is an exported symbol in the bin and retrieve it.

        Also test that the KeyError exception is raised when symbol not in bin.
        """
        exp_symb: Symbol = request.getfixturevalue(exp_symb)  # type: ignore
        assert example_bin.get_exported_symbol(exp_symb.name) == exp_symb
        with pytest.raises(KeyError) as excinfo:
            empty_bin.get_exported_symbol(exp_symb.name)
        assert excinfo.type is KeyError
        assert excinfo.match(exp_symb.name)

    @pytest.mark.parametrize(
        "imp_symb", ["example_imp_symb", "example_imp_func"], ids=["Symbol", "Function"]
    )
    def test_get_imported_symbol(
        self,
        imp_symb: Symbol,  # type: ignore
        example_bin: Binary,
        empty_bin: Binary,
        request: pytest.FixtureRequest,
    ):
        """Check if a symbol is an imported symbol in the bin and retrieve it.

        Also test that the KeyError exception is raised when symbol not in bin.
        """
        imp_symb: Symbol = request.getfixturevalue(imp_symb)  # type: ignore
        assert example_bin.get_imported_symbol(imp_symb.name) == imp_symb
        with pytest.raises(KeyError) as excinfo:
            empty_bin.get_imported_symbol(imp_symb.name)
        assert excinfo.type is KeyError
        assert excinfo.match(imp_symb.name)

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [("empty_bin", []), ("example_bin", ["example_exp_symb", "example_exp_func"])],
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
        [("empty_bin", []), ("example_bin", ["example_imp_symb", "example_imp_func"])],
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
            (
                "example_bin",
                ["example_imp_symb", "example_imp_non_resolved_symb", "example_imp_func"],
            ),
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

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [
            ("empty_bin", []),
            ("example_bin", ["example_exp_func"]),
        ],
        ids=["Empty bin", "Example bin"],
    )
    def test_iter_exported_func(
        self,
        _bin: Binary,  # type: ignore
        expected: list[Symbol],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all the exported functions."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x) for x in expected]  # type: ignore
        assert sorted(_bin.iter_exported_functions()) == sorted(expected)

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [
            ("empty_bin", []),
            ("example_bin", ["example_exp_func"]),
        ],
        ids=["Empty bin", "Example bin"],
    )
    def test_iter_exported_func_names(
        self,
        _bin: Binary,  # type: ignore
        expected: list[Symbol],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all the exported functions names."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x).name for x in expected]  # type: ignore
        assert sorted(_bin.iter_exported_function_names()) == sorted(expected)

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [
            ("empty_bin", []),
            ("example_bin", ["example_int_func"]),
        ],
        ids=["Empty bin", "Example bin"],
    )
    def test_iter_not_exported_func(
        self,
        _bin: Binary,  # type: ignore
        expected: list[Symbol],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all the internal functions."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x) for x in expected]  # type: ignore
        assert sorted(_bin.iter_not_exported_functions()) == sorted(expected)

    @pytest.mark.parametrize(
        ["_bin", "expected"],
        [
            ("empty_bin", []),
            ("example_bin", ["example_int_func", "example_exp_func"]),
        ],
        ids=["Empty bin", "Example bin"],
    )
    def test_iter_func(
        self,
        _bin: Binary,  # type: ignore
        expected: list[Symbol],
        request: pytest.FixtureRequest,
    ):
        """Check if iterate over all the internal functions."""
        _bin: Binary = request.getfixturevalue(_bin)  # type: ignore
        expected = [request.getfixturevalue(x) for x in expected]  # type: ignore
        assert sorted(_bin.iter_functions()) == sorted(expected)

    @pytest.mark.parametrize("bin_", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
    def test_auxiliary_file(self, bin_: Binary, request: pytest.FixtureRequest):
        """Check auxiliary file return values and that exception are raised correctly."""
        bin_ = request.getfixturevalue(bin_)  # type: ignore
        old_real_path = bin_.real_path
        real_path = Path("/tmp/real_path") if old_real_path is None else old_real_path
        bin_.real_path = None
        with pytest.raises(AttributeError) as excinfo_no_real_path:
            _ = bin_.auxiliary_file(extension="json")
        assert issubclass(excinfo_no_real_path.type, AttributeError)
        bin_.real_path = real_path
        with pytest.raises(NameError) as excinfo_no_param:
            _ = bin_.auxiliary_file()
        assert issubclass(excinfo_no_param.type, NameError)
        with pytest.raises(NameError) as excinfo_both_param:
            _ = bin_.auxiliary_file(extension=".json", append=".json")
        assert issubclass(excinfo_both_param.type, NameError)
        assert bin_.auxiliary_file(extension=".json") == real_path.with_suffix(".json")
        assert bin_.auxiliary_file(append=".json") == real_path.with_suffix(
            bin_.real_path.suffix + ".json"
        )
        bin_.real_path = old_real_path


class TestFileSystem:
    """Unit tests for FileSystem class."""

    @pytest.mark.parametrize("fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"])
    def test_json_export_format(
        self, fs: FileSystem, tmp_path: Path, request: pytest.FixtureRequest
    ):
        """Check if json export create a JSON file."""
        fs = request.getfixturevalue(fs)  # type: ignore
        export_path = tmp_path / "export.json"
        fs.write(export_path)
        assert export_path.exists(), "JSON export file not created"
        assert json.loads(export_path.read_text()), "exported data cannot be loaded as JSON"

    @pytest.mark.parametrize("fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"])
    def test_binaries_serializer_error_handling(
        self, fs: FileSystem, request: pytest.FixtureRequest
    ):
        """Check exception are raised correctly for malformed binaries field."""
        fs = request.getfixturevalue(fs)  # type: ignore
        path = Path("/tmp/broken_path")
        fs.binaries[path] = None  # type: ignore # done to the purpose of the test
        fs._binary_names[path.name] = list()
        with pytest.raises(ValueError) as excinfo:
            fs.model_dump()
        assert issubclass(excinfo.type, ValueError)
        with pytest.raises(ValueError) as excinfo_json:
            fs.model_dump_json()
        assert issubclass(excinfo_json.type, ValueError)

    @pytest.fixture
    def serialized_fs_no_dict(
        self, empty_fs: FileSystem, example_fs: FileSystem, request: pytest.FixtureRequest
    ) -> list[SerializedFS]:
        """Replace fields value by something not a dict."""
        res = list()
        for fs in [SerializedFS.from_fs(empty_fs), SerializedFS.from_fs(example_fs)]:
            dump, dump_json = fs.dump, json.loads(fs.json)
            dump["binaries"], dump["symlinks"] = list(fs.dump["binaries"].keys()), None
            dump_json["binaries"], dump_json["symlinks"] = randint(1, 1000), randint(1, 1000)
            res.append(SerializedFS(dump=dump, json=json.dumps(dump_json)))
        return res

    @pytest.fixture
    def serialized_fs_no_path(self, example_fs: FileSystem) -> list[SerializedFS]:
        """Replace paths value by something not transformable in a path (binaries dict keys)."""
        dump = example_fs.model_dump()
        dump["binaries"] = {str(k).encode(): v for k, v in dump["binaries"].items()}
        dump_json = json.loads(example_fs.model_dump_json())
        dump_json["binaries"] = {len(k.encode()): v for k, v in dump_json["binaries"].items()}
        return [SerializedFS(dump=dump, json=json.dumps(dump_json))]

    @pytest.fixture
    def serialized_fs_no_bin_content(self, example_fs: FileSystem) -> list[SerializedFS]:
        """Binaries dict contains one empty value."""
        dump = example_fs.model_dump()
        dump["binaries"][next(iter(dump["binaries"].keys()))] = "toto"
        dump_json = json.loads(example_fs.model_dump_json())
        dump_json["binaries"][next(iter(dump_json["binaries"].keys()))] = "toto"
        return [SerializedFS(dump=dump, json=json.dumps(dump_json))]

    @pytest.mark.parametrize(
        "dumps",
        ["serialized_fs_no_dict", "serialized_fs_no_path", "serialized_fs_no_bin_content"],
        ids=[
            "Fields not a dict",
            "Binaries dict keys not Path",
            "Missing one content for binaries field dict",
        ],
    )
    def test_binaries_validator_error_handling(
        self, dumps: list[SerializedFS], request: pytest.FixtureRequest
    ):
        """Check exception are raised correctly for malformed binaries field."""
        for data in request.getfixturevalue(dumps):  # type: ignore
            with pytest.raises(ValueError) as excinfo:
                FileSystem.model_validate(data.dump)
            assert issubclass(excinfo.type, ValueError)
            with pytest.raises(ValueError) as excinfo_json:
                FileSystem.model_validate_json(data.json)
            assert issubclass(excinfo_json.type, ValueError)

    @pytest.mark.parametrize("fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"])
    def test_json_dump_and_load(self, fs: FileSystem, tmp_path, request: pytest.FixtureRequest):
        """JSON dump then reload. Check if original and new are the same."""
        fs = request.getfixturevalue(fs)  # type: ignore
        dump = fs.model_dump_json()
        res = FileSystem.model_validate_json(dump)
        assert isinstance(res, FileSystem), "Loaded object not a FileSystem"
        assert res == fs, "Loaded class is different from the original"

    @pytest.mark.parametrize("fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"])
    def test_dump_and_load(self, fs: FileSystem, tmp_path, request: pytest.FixtureRequest):
        """Dump then reload. Check if original and new are the same."""
        fs = request.getfixturevalue(fs)  # type: ignore
        dump = fs.model_dump()
        res = FileSystem.model_validate(dump)
        assert isinstance(res, FileSystem), "Loaded object not a FileSystem"
        assert res == fs, "Loaded class is different from the original"

    @pytest.mark.parametrize("fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"])
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

    @pytest.mark.parametrize("fs", ["empty_fs", "example_fs"], ids=["Empty FS", "Example FS"])
    def test_add_symlink(self, fs: FileSystem, example_bin, request: pytest.FixtureRequest):  # type: ignore
        """Add a symlink and check it can be retrieved with FS methods."""
        fs = request.getfixturevalue(fs)  # type: ignore
        sym = Symlink(
            id=19,
            path=Path("/bin/my_second_symlink"),
            target=example_bin,
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
            target=example_sym,  # type: ignore
        )
        example_fs.add_symlink(rec_sym)
        assert example_fs.resolve_symlink(rec_sym) == example_bin

    def test_resolve_none_symlink(
        self, example_fs: FileSystem, example_bin: Binary, example_sym: Symlink
    ):
        """Check symlink which point on a non existing binary resolution."""
        non_existing_bin = Binary(path=Path("/tmp/non_existing"))
        rec_sym = Symlink(
            id=29,
            path=Path("/tmp/rec_symlink"),
            target=non_existing_bin,
        )
        example_fs.add_symlink(rec_sym)
        assert example_fs.resolve_symlink(rec_sym) is None
