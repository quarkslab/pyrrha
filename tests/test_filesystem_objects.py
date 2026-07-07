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
"""Unit test for FS objects. Pydantic classes are not tested if not modified."""

import json
from pathlib import Path
from random import randint
from typing import NamedTuple, Self

import pytest

from pyrrha_mapper import Binary, FileSystem, Symbol, Symlink
from pyrrha_mapper.mappers.objects import TargetType


class SerializedFS(NamedTuple):
    """NamedTuple which store both the classic dump and the json one of the same fs."""

    dump: dict
    json: str

    @classmethod
    def from_fs(cls, fs: FileSystem) -> Self:
        """:return: a SerializedFS generated from the given fs."""
        return cls(dump=fs.model_dump(), json=fs.model_dump_json())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_bin() -> Binary:
    """:return: an empty binary (no imports, no exports, only a path)."""
    return Binary(path=Path("/bin/test_empty"), id=0)


@pytest.fixture
def example_imp_symb() -> Symbol:
    """:return: the symbol used as imported symbol in example_bin."""
    return Symbol(name="exemple", is_func=False, id=1, demangled_name="exemple")


@pytest.fixture
def example_imp_func() -> Symbol:
    """:return: the symbol used as imported function in example_bin."""
    return Symbol(
        name="exemple_imp_func", is_func=True, id=12365, demangled_name="exemple_imp_func", addr=123
    )


@pytest.fixture
def example_imp_lib(example_imp_symb, example_imp_func) -> Binary:
    """:return: the binary used as imported lib in example_bin."""
    return Binary(
        id=3,
        path=Path("/lib/my_lib"),
        exported_symbols={example_imp_symb.name: example_imp_symb},
        exported_functions={example_imp_func.name: example_imp_func},
    )


@pytest.fixture
def example_imp_non_resolved_lib() -> Binary:
    """:return: the binary used of an non resolved imported lib in example_bin."""
    return Binary(path=Path("non_resolved_lib"))


@pytest.fixture
def example_imp_non_resolved_symb() -> Symbol:
    """:return: the binary used of an non resolved imported symbol in example_bin."""
    return Symbol(name="non_resolved_symb", demangled_name="non_resolved_symb")


@pytest.fixture
def example_exp_func() -> Symbol:
    """:return: the symbol used as exported func in example_bin."""
    return Symbol(name="my_func", is_func=True, id=2, demangled_name="my_func", addr=24)


@pytest.fixture
def example_int_func() -> Symbol:
    """:return: the symbol used as internal func in example_bin."""
    return Symbol(name="my_int_func", is_func=True, id=200, demangled_name="my_int_func", addr=25)


@pytest.fixture
def example_exp_symb() -> Symbol:
    """:return: the symbol used as exported symbol in example_bin."""
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
    """:return: a binary for tests."""
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
    """:return: a FileSystem instance with no binaries or symlinks."""
    return FileSystem(root_dir=Path("/tmp/foo"))


@pytest.fixture
def example_sym(example_bin):
    """:return: a Symlink which points on the example binary."""
    return Symlink(
        id=10,
        path=Path("/bin/my_symlink"),
        target=example_bin,
    )


@pytest.fixture
def example_fs(empty_bin, example_bin, example_sym, example_imp_lib):
    """:return: an FileSystem instance with two binaries and one symlink."""
    return FileSystem(
        root_dir=Path("/tmp/foo"),
        binaries={
            empty_bin.path: empty_bin,
            example_bin.path: example_bin,
            example_imp_lib.path: example_imp_lib,
        },
        symlinks={example_sym.path: example_sym},
    )


# ---------------------------------------------------------------------------
# TestFileSystemComponent
# ---------------------------------------------------------------------------


class TestFileSystemComponent:
    """Unit tests for FileSystemComponent base class."""

    @pytest.fixture
    def fsc_a(self) -> Binary:
        """:return: a FileSystemComponent instance (via Binary) for ordering tests."""
        return Binary(path=Path("/a/tool"))

    @pytest.fixture
    def fsc_b(self) -> Binary:
        """:return: a FileSystemComponent instance (via Binary) for ordering tests."""
        return Binary(path=Path("/b/tool"))

    def test_name_set_from_path(self, fsc_a: Binary):
        """model_post_init must set name to the last path component."""
        assert fsc_a.name == "tool"

    def test_lt(self, fsc_a: Binary, fsc_b: Binary):
        """__lt__ must order by model_dump tuple."""
        assert fsc_a < fsc_b

    def test_le(self, fsc_a: Binary, fsc_b: Binary):
        """__le__ must return True for a < b and True for a <= a."""
        assert fsc_a <= fsc_b
        assert fsc_a <= fsc_a

    def test_gt(self, fsc_a: Binary, fsc_b: Binary):
        """__gt__ must be the inverse of __lt__."""
        assert fsc_b > fsc_a

    def test_ge(self, fsc_a: Binary, fsc_b: Binary):
        """__ge__ must return True for b > a and True for a >= a."""
        assert fsc_b >= fsc_a
        assert fsc_a >= fsc_a


# ---------------------------------------------------------------------------
# TestSymbol
# ---------------------------------------------------------------------------


class TestSymbol:
    """Unit tests for Symbol class."""

    def test_repr(self, example_exp_func: Symbol):
        """Check repr format."""
        assert repr(example_exp_func) == f"Symbol('{example_exp_func.name}')"

    def test_hash_consistency(self, example_exp_func: Symbol):
        """Same symbol must always produce the same hash."""
        assert hash(example_exp_func) == hash(example_exp_func)

    def test_hash_different_symbols(self, example_exp_func: Symbol, example_int_func: Symbol):
        """Two distinct symbols must have different hashes."""
        assert hash(example_exp_func) != hash(example_int_func)

    def test_ordering(self, example_exp_func: Symbol, example_int_func: Symbol):
        """Check that ordering operators are consistent."""
        symbols = sorted([example_int_func, example_exp_func])
        assert symbols == sorted([example_exp_func, example_int_func])

    def test_lt(self, example_exp_func: Symbol, example_int_func: Symbol):
        """__lt__ must agree with __gt__ on reversed operands."""
        a, b = sorted([example_exp_func, example_int_func])
        assert a < b
        assert b > a

    def test_le_ge(self, example_exp_func: Symbol):
        """A symbol must be <= and >= itself."""
        assert example_exp_func <= example_exp_func
        assert example_exp_func >= example_exp_func

    def test_non_function_symbol(self):
        """A symbol with is_func=False must not be treated as a function."""
        symb = Symbol(name="data_sym", demangled_name="data_sym", is_func=False)
        assert not symb.is_func

    def test_addr_is_frozen(self, example_exp_func: Symbol):
        """The addr field is frozen: assignment must raise a ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            example_exp_func.addr = 9999  # type: ignore


# ---------------------------------------------------------------------------
# TestBinary
# ---------------------------------------------------------------------------


class TestBinary:
    """Unit tests for Binary class."""

    @pytest.mark.parametrize("_bin", ["empty_bin", "example_bin"], ids=["Empty bin", "Example bin"])
    def test_add_imported_library_name(self, _bin, request: pytest.FixtureRequest):
        """Check if the name is added correctly and can be retrieved."""
        _bin = request.getfixturevalue(_bin)  # type: ignore
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

    def test_repr(self, example_bin: Binary):
        """Check repr format."""
        assert repr(example_bin) == f"Binary('{example_bin.path}')"

    def test_name_derived_from_path(self):
        """Binary.name must equal the last component of its path."""
        binary = Binary(path=Path("/usr/lib/libfoo.so"))
        assert binary.name == "libfoo.so"

    def test_validate_functions_field_rejects_non_function(self):
        """internal_functions and exported_functions must only contain is_func=True symbols."""
        from pydantic import ValidationError

        non_func = Symbol(name="data", demangled_name="data", is_func=False)
        with pytest.raises(ValidationError):
            Binary(
                path=Path("/bin/bad"),
                internal_functions={"data": non_func},
            )
        with pytest.raises(ValidationError):
            Binary(
                path=Path("/bin/bad"),
                exported_functions={"data": non_func},
            )

    def test_image_base_excluded_from_serialization(self, empty_bin: Binary):
        """image_base must not appear in model_dump output (exclude=True)."""
        empty_bin.image_base = 0x400000
        dump = empty_bin.model_dump()
        assert "image_base" not in dump

    def test_version_requirement_field(self, empty_bin: Binary):
        """version_requirement must store symbol-to-requirements mappings."""
        empty_bin.version_requirement["malloc"] = ["GLIBC_2.5", "GLIBC_2.17"]
        assert empty_bin.version_requirement["malloc"] == ["GLIBC_2.5", "GLIBC_2.17"]

    def test_add_exported_symbol_function_goes_to_exported_functions(self, empty_bin: Binary):
        """add_exported_symbol with a function symbol must populate exported_functions."""
        func = Symbol(name="my_new_func", demangled_name="my_new_func", is_func=True, addr=100)
        empty_bin.add_exported_symbol(func)
        assert empty_bin.exported_function_exists(func.name), (
            "Function not found in exported_functions"
        )
        assert not empty_bin.exported_symbols.get(func.name), (
            "Function must not appear in exported_symbols"
        )

    def test_add_exported_symbol_non_function_goes_to_exported_symbols(self, empty_bin: Binary):
        """add_exported_symbol with a non-function must populate exported_symbols."""
        symb = Symbol(name="my_data", demangled_name="my_data", is_func=False)
        empty_bin.add_exported_symbol(symb)
        assert symb.name in empty_bin.exported_symbols
        assert symb.name not in empty_bin.exported_functions

    def test_add_exported_symbol_with_custom_name(self, empty_bin: Binary):
        """add_exported_symbol should store symbol under the provided symbol_name."""
        func = Symbol(name="orig_name", demangled_name="orig_name", is_func=True, addr=200)
        empty_bin.add_exported_symbol(func, symbol_name="alias_name")
        assert empty_bin.exported_function_exists("alias_name")
        assert not empty_bin.exported_function_exists("orig_name")

    def test_add_exported_symbol_overrides_previous_entry(self, empty_bin: Binary):
        """add_exported_symbol must replace an existing entry with the same name."""
        func_v1 = Symbol(name="versioned", demangled_name="versioned", is_func=True, addr=1)
        func_v2 = Symbol(name="versioned", demangled_name="versioned", is_func=True, addr=2)
        empty_bin.add_exported_symbol(func_v1)
        empty_bin.add_exported_symbol(func_v2)
        assert empty_bin.get_exported_symbol("versioned") == func_v2

    def test_add_exported_symbol_switches_type(self, empty_bin: Binary):
        """Replacing a non-function export with a function export."""
        symb = Symbol(name="swap_me", demangled_name="swap_me", is_func=False)
        func = Symbol(name="swap_me", demangled_name="swap_me", is_func=True, addr=300)
        empty_bin.add_exported_symbol(symb)
        assert "swap_me" in empty_bin.exported_symbols
        empty_bin.add_exported_symbol(func)
        assert "swap_me" not in empty_bin.exported_symbols
        assert "swap_me" in empty_bin.exported_functions

    def test_add_function(self, empty_bin: Binary):
        """add_function must make the function retrievable via provided methods."""
        func = Symbol(name="internal_fn", demangled_name="internal_fn", is_func=True, addr=50)
        empty_bin.add_function(func)
        assert empty_bin.function_exists(func.name)
        assert empty_bin.get_function_by_name(func.name) == func

    def test_add_function_with_custom_name(self, empty_bin: Binary):
        """add_function should store function under the provided func_name."""
        func = Symbol(name="real_name", demangled_name="real_name", is_func=True, addr=60)
        empty_bin.add_function(func, func_name="alias")
        assert empty_bin.function_exists("alias")
        assert not empty_bin.function_exists("real_name")

    def test_remove_function_internal(self, example_bin: Binary, example_int_func: Symbol):
        """remove_function must remove an internal function and its call entries."""
        example_bin.remove_function(example_int_func.name)
        assert not example_bin.function_exists(example_int_func.name)
        assert example_int_func.name not in example_bin.calls

    def test_remove_function_exported(self, example_bin: Binary, example_exp_func: Symbol):
        """remove_function must remove an exported function."""
        example_bin.remove_function(example_exp_func.name)
        assert not example_bin.function_exists(example_exp_func.name)

    def test_remove_function_raises_on_missing(self, empty_bin: Binary):
        """remove_function must raise KeyError for an unknown function name."""
        with pytest.raises(KeyError):
            empty_bin.remove_function("does_not_exist")

    def test_remove_imported_symbol(self, example_bin: Binary, example_imp_symb: Symbol):
        """remove_imported_symbol must remove symbol from imported_symbols."""
        example_bin.remove_imported_symbol(example_imp_symb.name)
        assert not example_bin.imported_symbol_exists(example_imp_symb.name, is_resolved=False)

    def test_get_function_by_name_internal(self, example_bin: Binary, example_int_func: Symbol):
        """get_function_by_name must retrieve internal functions."""
        assert example_bin.get_function_by_name(example_int_func.name) == example_int_func

    def test_get_function_by_name_exported(self, example_bin: Binary, example_exp_func: Symbol):
        """get_function_by_name must retrieve exported functions."""
        assert example_bin.get_function_by_name(example_exp_func.name) == example_exp_func

    def test_get_function_by_name_raises_on_missing(self, empty_bin: Binary):
        """get_function_by_name must raise KeyError for an unknown name."""
        with pytest.raises(KeyError):
            empty_bin.get_function_by_name("ghost_func")

    def test_imported_symbol_exists_unresolved(
        self, example_bin: Binary, example_imp_non_resolved_symb: Symbol
    ):
        """imported_symbol_exists(is_resolved=False) must return True for unresolved symbols."""
        assert example_bin.imported_symbol_exists(
            example_imp_non_resolved_symb.name, is_resolved=False
        )

    def test_imported_symbol_exists_resolved_flag(
        self, example_bin: Binary, example_imp_non_resolved_symb: Symbol
    ):
        """imported_symbol_exists(is_resolved=True) must return False for unresolved symbols."""
        assert not example_bin.imported_symbol_exists(
            example_imp_non_resolved_symb.name, is_resolved=True
        )

    def test_imported_library_exists_unresolved(
        self, example_bin: Binary, example_imp_non_resolved_lib: Binary
    ):
        """imported_library_exists(is_resolved=False) must return True for unresolved libs."""
        assert example_bin.imported_library_exists(
            example_imp_non_resolved_lib.name, is_resolved=False
        )

    def test_imported_library_exists_resolved_flag(
        self, example_bin: Binary, example_imp_non_resolved_lib: Binary
    ):
        """imported_library_exists(is_resolved=True) must return False for unresolved libs."""
        assert not example_bin.imported_library_exists(
            example_imp_non_resolved_lib.name, is_resolved=True
        )

    def test_add_imported_library_resolves_previously_none(
        self, example_bin: Binary, example_imp_non_resolved_lib: Binary
    ):
        """add_imported_library must replace a None entry with the resolved Binary."""
        example_bin.add_imported_library(example_imp_non_resolved_lib)
        assert example_bin.imported_library_exists(
            example_imp_non_resolved_lib.name, is_resolved=True
        )

    def test_get_imported_symbol_raises_for_non_resolved(
        self, example_bin: Binary, example_imp_non_resolved_symb: Symbol
    ):
        """get_imported_symbol must raise KeyError when the symbol value is None."""
        with pytest.raises(KeyError):
            example_bin.get_imported_symbol(example_imp_non_resolved_symb.name)

    def test_exported_function_exists_returns_false_for_unknown(self, empty_bin: Binary):
        """exported_function_exists must return False for a name not in the binary."""
        assert not empty_bin.exported_function_exists("no_such_func")

    def test_add_call_creates_new_entry_for_new_caller(
        self, example_bin: Binary, example_exp_func: Symbol
    ):
        """add_call must create a new calls list when the caller has no prior entries."""
        callee = Symbol(name="fresh_callee", demangled_name="fresh_callee", is_func=True, addr=500)
        assert example_exp_func.name not in example_bin.calls
        example_bin.add_call(example_exp_func, callee)
        assert example_bin.calls[example_exp_func.name] == [callee]

    def test_add_call_new_caller(self, example_bin: Binary, example_int_func: Symbol):
        """add_call with a new callee must append to existing call list."""
        new_callee = Symbol(name="new_target", demangled_name="new_target", is_func=True, addr=999)
        original_calls = list(example_bin.get_calls_from(example_int_func))
        example_bin.add_call(example_int_func, new_callee)
        updated_calls = example_bin.get_calls_from(example_int_func)
        assert new_callee in updated_calls
        assert len(updated_calls) == len(original_calls) + 1

    def test_add_call_no_duplicate(
        self, example_bin: Binary, example_int_func: Symbol, example_imp_func: Symbol
    ):
        """add_call must not add a duplicate callee."""
        original_calls = list(example_bin.get_calls_from(example_int_func))
        example_bin.add_call(example_int_func, example_imp_func)
        assert example_bin.get_calls_from(example_int_func) == original_calls

    def test_add_call_string_caller(self, example_bin: Binary, example_int_func: Symbol):
        """add_call must accept a caller given as a string name."""
        new_callee = Symbol(name="str_callee", demangled_name="str_callee", is_func=True, addr=888)
        example_bin.add_call(example_int_func.name, new_callee)
        assert new_callee in example_bin.get_calls_from(example_int_func.name)

    def test_add_call_raises_for_unknown_caller(self, empty_bin: Binary):
        """add_call must raise AssertionError when the caller is not in the binary."""
        callee = Symbol(name="callee", demangled_name="callee", is_func=True, addr=1)
        with pytest.raises(AssertionError):
            empty_bin.add_call("non_existing_caller", callee)

    def test_get_calls_from_symbol_arg(self, example_bin: Binary, example_int_func: Symbol):
        """get_calls_from must accept a Symbol argument and resolve it by name."""
        calls = example_bin.get_calls_from(example_int_func)
        assert calls == example_bin.calls[example_int_func.name]

    def test_get_calls_from_no_calls(self, empty_bin: Binary):
        """get_calls_from must return an empty list for a caller with no recorded calls."""
        assert empty_bin.get_calls_from("unknown") == []

    def test_exported_funcs_by_addr(self, example_bin: Binary, example_exp_func: Symbol):
        """exported_funcs_by_addr must index exported functions by their address."""
        by_addr = example_bin.exported_funcs_by_addr
        assert example_exp_func.addr in by_addr
        assert example_exp_func in by_addr[example_exp_func.addr]

    def test_exported_funcs_by_addr_multiple_at_same_addr(self, empty_bin: Binary):
        """exported_funcs_by_addr must group multiple functions sharing the same address."""
        func_a = Symbol(name="alias_a", demangled_name="alias_a", is_func=True, addr=42)
        func_b = Symbol(name="alias_b", demangled_name="alias_b", is_func=True, addr=42)
        empty_bin.add_exported_symbol(func_a)
        empty_bin.add_exported_symbol(func_b)
        by_addr = empty_bin.exported_funcs_by_addr
        assert 42 in by_addr
        assert func_a in by_addr[42]
        assert func_b in by_addr[42]

    def test_exported_funcs_by_addr_skips_none_addr(self, empty_bin: Binary):
        """exported_funcs_by_addr must not include functions with addr=None."""
        func_no_addr = Symbol(name="no_addr_func", demangled_name="no_addr_func", is_func=True)
        empty_bin.add_exported_symbol(func_no_addr)
        assert empty_bin.exported_funcs_by_addr == {}

    def test_replace_function_exported_keep_old_name(
        self, example_bin: Binary, example_exp_func: Symbol
    ):
        """replace_function with keep_old_name=True on an exported function must keep old name."""
        new_func = Symbol(name="replacement", demangled_name="replacement", is_func=True, addr=777)
        example_bin.replace_function(new_func, example_exp_func, keep_old_name=True)
        assert example_bin.get_exported_symbol(example_exp_func.name) == new_func
        assert not example_bin.exported_function_exists(new_func.name)

    def test_replace_function_exported_new_name(
        self, example_bin: Binary, example_exp_func: Symbol
    ):
        """replace_function with keep_old_name=False on an exported function uses new name."""
        new_func = Symbol(name="replacement", demangled_name="replacement", is_func=True, addr=778)
        example_bin.replace_function(new_func, example_exp_func, keep_old_name=False)
        assert example_bin.exported_function_exists(new_func.name)
        assert not example_bin.exported_function_exists(example_exp_func.name)

    def test_replace_function_internal_keep_old_name(
        self, example_bin: Binary, example_int_func: Symbol
    ):
        """replace_function with keep_old_name=True on an internal function must update it."""
        new_func = Symbol(
            name="new_internal", demangled_name="new_internal", is_func=True, addr=900
        )
        example_bin.replace_function(new_func, example_int_func, keep_old_name=True)
        assert example_bin.get_function_by_name(example_int_func.name) == new_func
        assert not example_bin.function_exists(new_func.name)

    def test_replace_function_internal_new_name(
        self, example_bin: Binary, example_int_func: Symbol
    ):
        """replace_function with keep_old_name=False on an internal function uses new name."""
        new_func = Symbol(
            name="new_internal", demangled_name="new_internal", is_func=True, addr=901
        )
        example_bin.replace_function(new_func, example_int_func, keep_old_name=False)
        assert example_bin.function_exists(new_func.name)
        assert not example_bin.function_exists(example_int_func.name)

    def test_replace_function_noop_when_equal(self, example_bin: Binary, example_exp_func: Symbol):
        """replace_function must be a no-op when old and new functions are identical."""
        before = dict(example_bin.exported_functions)
        example_bin.replace_function(example_exp_func, example_exp_func, keep_old_name=True)
        assert example_bin.exported_functions == before

    def test_exported_function_exists_for_exported_function(
        self, example_bin: Binary, example_exp_func: Symbol
    ):
        """exported_function_exists must return True for an exported function."""
        assert example_bin.exported_function_exists(example_exp_func.name)

    def test_exported_symbol_exists_via_exported_function(
        self, example_bin: Binary, example_exp_func: Symbol
    ):
        """exported_symbol_exists must return True even for symbols in exported_functions."""
        assert example_bin.exported_symbol_exists(example_exp_func.name)


# ---------------------------------------------------------------------------
# TestSymlink
# ---------------------------------------------------------------------------


class TestSymlink:
    """Unit tests for Symlink class."""

    def test_repr(self, example_sym: Symlink, example_bin: Binary):
        """Check repr format."""
        assert repr(example_sym) == f"Symlink({example_sym.path} -> {example_bin.path})"

    def test_target_type_binary(self, example_sym: Symlink):
        """target_type must be BINARY when the target is a Binary."""
        assert example_sym.target_type is TargetType.BINARY

    def test_target_type_symlink(self, example_sym: Symlink, example_bin: Binary):
        """target_type must be SYMLINK when the target is a Symlink."""
        nested_sym = Symlink(path=Path("/bin/nested_sym"), target=example_sym)
        assert nested_sym.target_type is TargetType.SYMLINK

    def test_target_type_raises_for_invalid_target(self, example_bin: Binary):
        """target_type must raise ValueError when target is neither a Binary nor a Symlink."""
        from unittest.mock import patch

        sym = Symlink(path=Path("/bin/bad_sym"), target=example_bin)
        with patch.object(sym, "target", new=object()):
            with pytest.raises(
                ValueError, match="Target is not a Binary object neither a Symlink one."
            ):
                _ = sym.target_type

    def test_target_path(self, example_sym: Symlink, example_bin: Binary):
        """target_path must equal the path of the target object."""
        assert example_sym.target_path == example_bin.path

    def test_name_derived_from_path(self, example_sym: Symlink):
        """Symlink.name must equal the last component of its path."""
        assert example_sym.name == example_sym.path.name


# ---------------------------------------------------------------------------
# TestFileSystem
# ---------------------------------------------------------------------------


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

    def test_repr(self, example_fs: FileSystem):
        """Check repr format."""
        assert repr(example_fs) == (
            f"FileSystem(root='{example_fs.root_dir}',"
            f"bins={len(example_fs.binaries)}, symlinks={len(example_fs.symlinks)})"
        )

    def test_from_json_export_roundtrip(self, example_fs: FileSystem, tmp_path: Path):
        """Write to disk then reload via from_json_export; result must equal original."""
        export_path = tmp_path / "fs.json"
        example_fs.write(export_path)
        reloaded = FileSystem.from_json_export(export_path)
        assert reloaded == example_fs

    def test_from_json_export_accepts_str_path(self, example_fs: FileSystem, tmp_path: Path):
        """from_json_export must also accept a plain string path."""
        export_path = tmp_path / "fs.json"
        example_fs.write(export_path)
        reloaded = FileSystem.from_json_export(str(export_path))
        assert reloaded == example_fs

    def test_binary_exists_by_path(self, example_fs: FileSystem, example_bin: Binary):
        """binary_exists must accept a Path argument as well as a Binary."""
        assert example_fs.binary_exists(example_bin.path)

    def test_symlink_exists_by_path(self, example_fs: FileSystem, example_sym: Symlink):
        """symlink_exists must accept a Path argument as well as a Symlink."""
        assert example_fs.symlink_exists(example_sym.path)

    def test_real_path_set_after_add_binary(self, empty_fs: FileSystem):
        """add_binary must set real_path on the binary object."""
        _bin = Binary(path=Path("/usr/bin/tool"))
        empty_fs.add_binary(_bin)
        assert _bin.real_path is not None
        assert _bin.real_path == Path(empty_fs.root_dir) / ("." + str(_bin.path))

    def test_real_path_set_after_add_symlink(self, empty_fs: FileSystem, example_bin: Binary):
        """add_symlink must set real_path on the symlink object."""
        empty_fs.add_binary(example_bin)
        sym = Symlink(path=Path("/usr/bin/tool_link"), target=example_bin)
        empty_fs.add_symlink(sym)
        assert sym.real_path is not None
        assert sym.real_path == Path(empty_fs.root_dir) / ("." + str(sym.path))

    def test_gen_fw_path(self, example_fs: FileSystem, example_bin: Binary):
        """gen_fw_path must return a firmware-rooted path for a host absolute path."""
        host_path = example_fs.root_dir / ("." + str(example_bin.path)).lstrip("/")
        fw_path = example_fs.gen_fw_path(host_path)
        # Result must be rooted at the filesystem anchor (e.g. "/")
        assert fw_path.is_absolute()

    def test_symlinks_serializer_error_handling(self, example_fs: FileSystem):
        """Symlinks serializer must raise ValueError when a symlink value is None."""
        path = Path("/tmp/broken_sym")
        example_fs.symlinks[path] = None  # type: ignore # done to the purpose of the test
        example_fs._symlink_names[path.name] = list()
        with pytest.raises(ValueError) as excinfo:
            example_fs.model_dump()
        assert issubclass(excinfo.type, ValueError)
        with pytest.raises(ValueError) as excinfo_json:
            example_fs.model_dump_json()
        assert issubclass(excinfo_json.type, ValueError)

    def test_binaries_validator_deduplicates_symbols_by_id(self):
        """fs_bin_validate must unify imported symbol objects that share the same id."""
        shared_sym = Symbol(name="shared", demangled_name="shared", is_func=False, id=42)
        lib = Binary(
            path=Path("/lib/libshared.so"),
            exported_symbols={shared_sym.name: shared_sym},
        )
        consumer = Binary(
            path=Path("/bin/consumer"),
            imported_symbols={shared_sym.name: shared_sym},
        )
        fs = FileSystem(
            root_dir=Path("/tmp/fw"),
            binaries={lib.path: lib, consumer.path: consumer},
        )
        dump = fs.model_dump_json()
        reloaded = FileSystem.model_validate_json(dump)
        # After reload, the imported symbol in consumer must be the same object
        # as the exported symbol in lib (unified by id).
        reloaded_lib_sym = reloaded.get_binary_by_path(lib.path).get_exported_symbol(
            shared_sym.name
        )
        reloaded_consumer_sym = reloaded.get_binary_by_path(consumer.path).get_imported_symbol(
            shared_sym.name
        )
        assert reloaded_lib_sym is reloaded_consumer_sym

    def test_binaries_validator_fastpath_already_validated(self, example_fs: FileSystem):
        """fs_bin_validate fast-path must return immediately when data is already well typed."""
        dump = example_fs.model_dump()
        dump["binaries"] = example_fs.binaries  # already dict[Path, Binary]
        reloaded = FileSystem.model_validate(dump)
        assert reloaded.binaries == example_fs.binaries

    def test_symlinks_validator_fastpath_already_validated(self, example_fs: FileSystem):
        """fs_sym_validate fast-path must return immediately when data is already well typed."""
        dump = example_fs.model_dump()
        dump["binaries"] = example_fs.binaries
        dump["symlinks"] = example_fs.symlinks  # already dict[Path, Symlink]
        reloaded = FileSystem.model_validate(dump)
        assert reloaded.symlinks == example_fs.symlinks

    def test_symlinks_validator_symlink_instance_fastpath(
        self, example_fs: FileSystem, example_sym: Symlink, example_bin: Binary
    ):
        """fs_sym_validate: a live Symlink instance in the dict must be stored directly."""
        dump = example_fs.model_dump()
        # Add a new symlink as a raw dict so the top-level fast-path (reduce) does not fire,
        # while keeping example_sym as a live Symlink object so lines 566-567 are reached.
        new_sym = Symlink(path=Path("/bin/extra_sym"), target=example_bin)
        dump["symlinks"][new_sym.path] = {
            "path": new_sym.path,
            "id": new_sym.id,
            "name": new_sym.name,
            "real_path": new_sym.real_path,
            "target": example_bin,
        }
        dump["symlinks"][example_sym.path] = example_sym  # live Symlink → hits lines 566-567
        reloaded = FileSystem.model_validate(dump)
        assert reloaded.symlink_exists(example_sym.path)
        assert reloaded.symlink_exists(new_sym.path)

    def test_symlinks_validator_symlink_chain_resolved(
        self, example_fs: FileSystem, example_bin: Binary, example_sym: Symlink
    ):
        """fs_sym_validate while-loop must resolve a multi-hop symlink-to-symlink chain."""
        # Use model_validate on a raw string-keyed dict (not model_validate_json) so that
        # the validator cannot take the fast-path and must run the while-loop resolution.
        dump = json.loads(example_fs.model_dump_json())
        # Build sym_mid → example_sym → example_bin, and sym_outer → sym_mid.
        # Both end up in untreated_symlinks, exercising multiple passes of the while-loop.
        dump["symlinks"]["/bin/sym_mid"] = {
            "path": "/bin/sym_mid",
            "id": 50,
            "name": "sym_mid",
            "real_path": None,
            "target_path": str(example_sym.path),
            "target_type": TargetType.SYMLINK.value,
        }
        dump["symlinks"]["/bin/sym_outer"] = {
            "path": "/bin/sym_outer",
            "id": 51,
            "name": "sym_outer",
            "real_path": None,
            "target_path": "/bin/sym_mid",
            "target_type": TargetType.SYMLINK.value,
        }
        reloaded = FileSystem.model_validate(dump)
        assert reloaded.symlink_exists(Path("/bin/sym_outer"))
        assert reloaded.resolve_symlink(
            reloaded.get_symlink_by_path(Path("/bin/sym_outer"))
        ) == reloaded.get_binary_by_path(example_bin.path)

    def test_symlinks_validator_error_unknown_target_path(self, example_fs: FileSystem):
        """fs_sym_validate must raise ValueError when a symlink-to-symlink target is missing."""
        dump = json.loads(example_fs.model_dump_json())
        # A symlink whose target_type is SYMLINK but target_path points nowhere.
        dump["symlinks"]["/dangling_sym_link"] = {
            "path": "/dangling_sym_link",
            "id": 55,
            "name": "dangling_sym_link",
            "real_path": None,
            "target_path": "/does/not/exist",
            "target_type": TargetType.SYMLINK.value,
        }
        with pytest.raises(ValueError):
            FileSystem.model_validate_json(json.dumps(dump))

    def test_symlinks_validator_error_non_dict_content(self, example_fs: FileSystem):
        """fs_sym_validate must raise ValueError when a symlink entry is not a dict."""
        dump = json.loads(example_fs.model_dump_json())
        dump["symlinks"]["/bad_sym"] = 12345
        with pytest.raises(ValueError):
            FileSystem.model_validate_json(json.dumps(dump))

    def test_symlinks_validator_error_bad_key_type(self, example_fs: FileSystem):
        """fs_sym_validate must raise ValueError when a symlink dict key cannot be converted."""
        dump = example_fs.model_dump()
        # bytes keys are not Path-convertible, triggering the TypeError branch.
        dump["symlinks"] = {b"/bad/key": v for _, v in dump["symlinks"].items()}  # noqa: B035
        with pytest.raises(ValueError):
            FileSystem.model_validate(dump)

    def test_symlinks_validator_error_invalid_target_path_type(self, example_fs: FileSystem):
        """fs_sym_validate must raise ValueError when target_path cannot be converted to Path."""
        dump = example_fs.model_dump()
        first_sym_key = next(iter(dump["symlinks"]))
        content = dict(dump["symlinks"][first_sym_key])
        content["target_path"] = object()  # not Path-convertible
        dump["symlinks"][Path("/bin/bad_target_path_sym")] = content
        with pytest.raises((ValueError, TypeError)):
            FileSystem.model_validate(dump)

    def test_finalize_sym_validation_resolves_symlink_target(
        self, example_fs: FileSystem, example_sym: Symlink
    ):
        """finalize_sym_validation must resolve a SYMLINK-type target to its Symlink object."""
        chain_sym = Symlink(path=Path("/bin/chain_sym"), target=example_sym)
        example_fs.add_symlink(chain_sym)
        # Use model_validate on a raw dict to force finalize_sym_validation to run
        # and resolve the SYMLINK branch (line 394).
        dump = json.loads(example_fs.model_dump_json())
        reloaded = FileSystem.model_validate(dump)
        reloaded_chain = reloaded.get_symlink_by_path(chain_sym.path)
        assert reloaded_chain.target_type is TargetType.SYMLINK

    def test_finalize_sym_validation_error_on_missing_target(self):
        """finalize_sym_validation must raise ValueError when a symlink target is absent."""
        bin_ = Binary(path=Path("/bin/real"))
        sym = Symlink(path=Path("/bin/link"), target=bin_)
        # Build the FS without adding bin_ to binaries, so finalize_sym_validation fails.
        with pytest.raises(ValueError):
            FileSystem(
                root_dir=Path("/tmp/fw"),
                binaries={},
                symlinks={sym.path: sym},
            )

    def test_finalize_sym_validation_invalid_target_type(
        self, example_fs: FileSystem, example_sym: Symlink
    ):
        """finalize_sym_validation must raise ValueError when target_type is not a valid enum."""
        from unittest.mock import PropertyMock, patch

        with patch.object(
            type(example_sym), "target_type", new_callable=PropertyMock, return_value="INVALID"
        ):
            with pytest.raises(ValueError):
                example_fs.finalize_sym_validation() # type: ignore

    def test_symlinks_validator_no_target_type_key(
        self, example_fs: FileSystem, example_bin: Binary
    ):
        """fs_sym_validate must call __symlink_convert when target_type/target_path are absent."""
        dump = example_fs.model_dump()
        raw_sym_dict = {
            "path": Path("/bin/raw_sym"),
            "id": 77,
            "name": "raw_sym",
            "real_path": None,
            "target": example_bin,
        }
        dump["symlinks"][Path("/bin/raw_sym")] = raw_sym_dict
        reloaded = FileSystem.model_validate(dump)
        assert reloaded.symlink_exists(Path("/bin/raw_sym"))

    def test_fs_bin_validate_error_on_path_mismatch(self, example_fs: FileSystem):
        """fs_bin_validate must raise ValueError when a binary path mismatches its dict key."""
        dump = example_fs.model_dump()
        first_key = next(iter(dump["binaries"]))
        content = dump["binaries"].pop(first_key)
        dump["binaries"][Path("/completely/different/path")] = content
        with pytest.raises(ValueError):
            FileSystem.model_validate(dump)

    def test_fs_bin_validate_error_on_missing_imported_lib(self, example_fs: FileSystem):
        """fs_bin_validate must raise ValueError when an imported lib path is absent."""
        dump = json.loads(example_fs.model_dump_json())
        for bin_data in dump["binaries"].values():
            if bin_data["imported_libraries"]:
                first_lib_name = next(
                    k for k, v in bin_data["imported_libraries"].items() if v is not None
                )
                bin_data["imported_libraries"][first_lib_name]["path"] = "/no/such/lib"
                break
        with pytest.raises(ValueError):
            FileSystem.model_validate_json(json.dumps(dump))

    def test_fs_bin_validate_error_on_bad_lib_path_type(self, example_fs: FileSystem):
        """fs_bin_validate must raise ValueError when a lib path value cannot be converted."""
        dump = json.loads(example_fs.model_dump_json())
        for bin_data in dump["binaries"].values():
            if bin_data["imported_libraries"]:
                first_lib_name = next(
                    k for k, v in bin_data["imported_libraries"].items() if v is not None
                )
                bin_data["imported_libraries"][first_lib_name] = {"path": None}
                break
        with pytest.raises(ValueError):
            FileSystem.model_validate_json(json.dumps(dump))

    def test_fs_sym_validate_error_on_path_mismatch(self, example_fs: FileSystem):
        """__symlink_convert must raise ValueError when a symlink path mismatches its key."""
        dump = json.loads(example_fs.model_dump_json())
        first_sym_key = next(iter(dump["symlinks"]))
        dump["symlinks"][first_sym_key]["path"] = "/completely/wrong/path"
        with pytest.raises(ValueError):
            FileSystem.model_validate_json(json.dumps(dump))

    def test_multiple_binaries_same_name(self, empty_fs: FileSystem):
        """Two binaries with same filename but different paths must both be retrievable by name."""
        bin_a = Binary(path=Path("/usr/bin/tool"))
        bin_b = Binary(path=Path("/usr/local/bin/tool"))
        empty_fs.add_binary(bin_a)
        empty_fs.add_binary(bin_b)
        by_name = empty_fs.get_binaries_by_name("tool")
        assert bin_a in by_name
        assert bin_b in by_name
        assert len(by_name) == 2

    def test_multiple_symlinks_same_name(self, empty_fs: FileSystem, example_bin: Binary):
        """Two symlinks with same filename but different paths must both be retrievable by name."""
        empty_fs.add_binary(example_bin)
        sym_a = Symlink(path=Path("/usr/bin/lnk"), target=example_bin)
        sym_b = Symlink(path=Path("/usr/local/bin/lnk"), target=example_bin)
        empty_fs.add_symlink(sym_a)
        empty_fs.add_symlink(sym_b)
        by_name = empty_fs.get_symlinks_by_name("lnk")
        assert sym_a in by_name
        assert sym_b in by_name
        assert len(by_name) == 2
