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
"""Backend-free unit tests for :mod:`intercg_bin_loader` pure logic.

The ``BinaryParser`` constructor launches a disassembler, so it is never run
here. The module-level helpers (``FuncData``, ``_count_leading_underscores``,
``_SYNTHETIC_FUNC_NAME_RE``) are tested directly, and the two pure instance
methods (``_build_calls_list`` and ``_disambiguate_export``) are exercised on a
parser built with ``object.__new__`` so only ``log_prefix`` needs to be set.
"""

from pyrrha_mapper.mappers.intercg_bin_loader import (
    _SYNTHETIC_FUNC_NAME_RE,
    BinaryParser,
    FuncData,
    _count_leading_underscores,
)
from pyrrha_mapper.mappers.objects import Symbol
from pyrrha_mapper.types import FuncType


def func_data(name: str, addr: int, *, demangled: str | None = None, calls=None) -> FuncData:
    """Build a FuncData with a function Symbol."""
    return FuncData(
        symbol=Symbol(
            name=name,
            demangled_name=demangled if demangled is not None else name,
            is_func=True,
            addr=addr,
        ),
        type=FuncType.NORMAL,
        calls=calls if calls is not None else [],
        callers=[],
    )


class _StubParser(BinaryParser):
    """Concrete BinaryParser with abstract backend methods stubbed.

    The pure methods under test (``_build_calls_list`` and
    ``_disambiguate_export``) do not call these accessors, so they raise if
    reached by mistake.
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


def make_parser() -> BinaryParser:
    """Build a BinaryParser without running its disassembler-launching __init__."""
    parser = object.__new__(_StubParser)
    parser.log_prefix = "[test]"
    return parser


# --------------------------------------------------------------------------- #
#  FuncData
# --------------------------------------------------------------------------- #


class TestFuncData:
    """Tests for the FuncData NamedTuple accessors."""

    def test_name_and_demangled(self) -> None:
        """Name and demangled_name proxy the underlying Symbol."""
        fd = func_data("_Zmangled", 0x10, demangled="readable")
        assert fd.name == "_Zmangled"
        assert fd.demangled_name == "readable"

    def test_addr(self) -> None:
        """Addr returns the Symbol address."""
        fd = func_data("f", 0x1234)
        assert fd.addr == 0x1234


# --------------------------------------------------------------------------- #
#  _count_leading_underscores
# --------------------------------------------------------------------------- #


class TestCountLeadingUnderscores:
    """Tests for the _count_leading_underscores helper."""

    def test_counts_underscores_and_dots(self) -> None:
        """Leading underscores and dots are both counted."""
        assert _count_leading_underscores("__foo") == 2
        assert _count_leading_underscores("._.bar") == 3
        assert _count_leading_underscores("baz") == 0
        assert _count_leading_underscores("") == 0


# --------------------------------------------------------------------------- #
#  _SYNTHETIC_FUNC_NAME_RE
# --------------------------------------------------------------------------- #


class TestSyntheticFuncNameRe:
    """Tests for the synthetic tool-generated name regex."""

    def test_matches_tool_generated_names(self) -> None:
        """FUN_/sub_/_INIT_/_FINI_ names match."""
        for name in ("FUN_00101234", "sub_deadbeef", "_INIT_0", "_FINI_12"):
            assert _SYNTHETIC_FUNC_NAME_RE.match(name) is not None

    def test_rejects_real_names(self) -> None:
        """Ordinary symbol names do not match."""
        for name in ("main", "FUN_xyz", "my_sub_routine", "_INIT_handler"):
            assert _SYNTHETIC_FUNC_NAME_RE.match(name) is None


# --------------------------------------------------------------------------- #
#  _build_calls_list
# --------------------------------------------------------------------------- #


class TestBuildCallsList:
    """Tests for BinaryParser._build_calls_list."""

    def test_collects_named_callees_in_graph(self) -> None:
        """Only callees present in the graph and bearing a name are returned."""
        parser = make_parser()
        callee_a = func_data("a", 0x20)
        callee_b = func_data("b", 0x30)
        caller = func_data("caller", 0x10, calls=[0x20, 0x30, 0x99])
        graph = {0x20: callee_a, 0x30: callee_b}  # 0x99 absent from graph
        out = parser._build_calls_list(caller, graph)
        assert out == ["a", "b"]

    def test_unnamed_callee_warns_and_skipped(self, caplog) -> None:
        """A callee with an empty name is skipped with a warning."""
        parser = make_parser()
        unnamed = func_data("", 0x20)
        caller = func_data("caller", 0x10, calls=[0x20])
        graph = {0x20: unnamed}
        with caplog.at_level("WARNING"):
            out = parser._build_calls_list(caller, graph)
        assert out == []
        assert any("unnamed function" in r.message for r in caplog.records)


# --------------------------------------------------------------------------- #
#  _disambiguate_export
# --------------------------------------------------------------------------- #


class TestDisambiguateExport:
    """Tests for BinaryParser._disambiguate_export."""

    def _sym(self, demangled: str) -> Symbol:
        return Symbol(name=demangled, demangled_name=demangled, is_func=True, addr=0x10)

    def test_single_symbol_returned(self) -> None:
        """A single candidate is returned unchanged."""
        parser = make_parser()
        only = self._sym("foo")
        assert parser._disambiguate_export([only]) is only

    def test_prefers_shortest_non_underscore(self) -> None:
        """The shortest name not starting with '_' is preferred."""
        parser = make_parser()
        a = self._sym("_internal")
        b = self._sym("public_long")
        c = self._sym("pub")
        chosen = parser._disambiguate_export([a, b, c])
        assert chosen is c

    def test_falls_back_to_shortest_when_all_underscored(self, caplog) -> None:
        """When all names start with '_', the globally shortest is chosen."""
        parser = make_parser()
        a = self._sym("__longer_name")
        b = self._sym("_x")
        with caplog.at_level("DEBUG"):
            chosen = parser._disambiguate_export([a, b])
        assert chosen is b
