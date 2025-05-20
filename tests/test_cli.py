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
"""Functionnal test from the CLI."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import NamedTuple

import pytest
from click import Command
from click.testing import CliRunner, Result

from pyrrha_mapper.__main__ import pyrrha
from pyrrha_mapper.common import FileSystem, Symbol
from pyrrha_mapper.intercg.fwmapper import InterImageCGMapper


class TestCLI:
    """Tests to check that the CLI works and display correct messages."""

    COMMAND: Command = pyrrha
    SUBCOMMANDS = pyrrha.commands

    def test_usage(self):
        """Display correctly main usage."""
        runner = CliRunner()
        res_short = runner.invoke(self.COMMAND, ["-h"])
        res_long = runner.invoke(self.COMMAND, ["--help"])
        for res in [res_long, res_short]:
            assert res.exit_code == 0
            assert res.output.startswith(f"Usage: {self.COMMAND.name}")
        assert res_short.output == res_long.output, "Usage different with -h/--help"

    @pytest.mark.parametrize("subcommand", SUBCOMMANDS)
    def test_subcommand_usage(self, subcommand: str):
        """Display correctly submcommand usage."""
        runner = CliRunner()
        res_short = runner.invoke(self.COMMAND, [subcommand, "-h"])
        res_long = runner.invoke(self.COMMAND, [subcommand, "--help"])
        for res in [res_long, res_short]:
            assert res.exit_code == 0
            assert res.output.startswith(f"Usage: {self.COMMAND.name} {subcommand}")
        assert res_short.output == res_long.output, "Usage different with -h/--help"


class BaseTestFsMapper(ABC):
    """Common tests for all fs* mapper."""

    COMMAND = pyrrha

    @property
    @abstractmethod
    def SUBCOMMAND(self) -> str:
        """To be implemented in concrete class, as class attribute."""
        ...

    FW_TEST_PATH = Path(__file__).parent / "test_fw"
    FW_TEST_LD = Path("/lib/ld-linux.so.3")
    FW_TEST_BIN_PATHS = {
        FW_TEST_LD,
        Path("/lib/libc.so.6"),
        Path("/lib/libcrypto.so.1.1"),
        Path("/lib/libdl.so.2"),
        Path("/lib/libpthread.so.0"),
        Path("/lib/libssl.so.1.1"),
        Path("/bin/openssl"),
    }
    FW_TEST_SYMLINKS_PATHS = {Path("/lib/libssl.so")}


    # =============================== INTERNAL STUFFS ==================================

    class ExecResults(NamedTuple):  # noqa: D106
        res: Result
        db_path: Path

        @property
        def export_path(self) -> Path:  # noqa: D102
            return self.db_path.with_suffix(".json")

    @staticmethod
    def _path_id(val):
        if isinstance(val, Path):
            return str(val)
        return val

    # =============================== FIXTURES ========================================

    @pytest.fixture(scope="class")
    def pyrrha_exec(self, request, tmp_path_factory) -> ExecResults:
        """Run pyrrha whith the given thread number and the given db path."""
        runner = CliRunner()
        tmp_path = (
            tmp_path_factory.mktemp("db", numbered=True)
            / f"{self.SUBCOMMAND}-{request.param}.srctrlprj"
        )
        args = [
            self.SUBCOMMAND,
            "--db",
            f"{tmp_path}",
            "-j",
            request.param,
            f"{self.FW_TEST_PATH}",
        ]
        return self.ExecResults(res=runner.invoke(self.COMMAND, args), db_path=tmp_path)

    @abstractmethod
    @pytest.fixture(scope="class")
    def export_res(self, tmp_path_factory, request) -> ExecResults:
        """Run Pyrrha with export activated."""
        ...

    @pytest.fixture(scope="class")
    def export_dump(self, export_res: ExecResults) -> FileSystem:
        """Load JSON export into a FileSystem object."""
        return FileSystem.from_json_export(export_res.export_path)

    # =================================== TESTS ========================================

    @pytest.mark.parametrize("pyrrha_exec", [1, 16], indirect=True)
    def test_numbat_project_creation(self, pyrrha_exec: ExecResults):
        """Two files are generated with correct extensions."""
        assert pyrrha_exec.res.exit_code == 0
        assert pyrrha_exec.db_path.exists()
        assert pyrrha_exec.db_path.with_suffix(".srctrldb").exists(), "Missing DB file"
        assert pyrrha_exec.db_path.with_suffix(".srctrlprj").exists(), "Missing project file"

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    def test_export_creation(self, export_res: ExecResults) -> None:
        """Export file exist."""
        assert export_res.res.exit_code == 0
        assert export_res.export_path.exists(), "Export file does not exist"

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    def test_export_format(self, export_dump: FileSystem) -> None:
        """JSON export is loaded as a Filesystem object."""
        assert isinstance(export_dump, FileSystem), "Export cannot be loaded correctly"

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    def test_binary_list(self, export_dump: FileSystem) -> None:
        """Firmware binaries are present in results."""
        assert {_bin.path for _bin in export_dump.iter_binaries()} == self.FW_TEST_BIN_PATHS, (
            "Missing binaries"
        )

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    def test_symlink_list(self, export_dump: FileSystem) -> None:
        """Firmware symlinks are present in results."""
        assert {sym.path for sym in export_dump.iter_symlinks()} == self.FW_TEST_SYMLINKS_PATHS, (
            "Missing symlinks"
        )

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_exported_symbols(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Exported symbols exist for each binary of the firware."""
        _bin = export_dump.get_binary_by_path(bin_path)
        assert len(list(_bin.iter_exported_symbols())) > 0, "Missing exported symbols"

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_dependencies(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported libraries exist for each binary of the firware except ldd."""
        _bin = export_dump.get_binary_by_path(bin_path)
        if bin_path == self.FW_TEST_LD:
            assert len(list(_bin.iter_imported_libraries())) == 0, "Create false imported libraries"
        else:
            assert len(list(_bin.iter_imported_libraries())) > 0, "Missing imported libraries"

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_resolved_dependencies(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported libraries correspond to a binary object."""
        _bin = export_dump.get_binary_by_path(bin_path)
        assert len(list(_bin.iter_imported_libraries())) == len(_bin.imported_library_names), (
            "Some imported libraries have not been resolved"
        )

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_imported_symbols(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported symbols exist for each binary of the firware except ldd."""
        _bin = export_dump.get_binary_by_path(bin_path)
        if bin_path == self.FW_TEST_LD:
            assert len(_bin.imported_symbol_names) == 0, "Create false imported symbols"
        else:
            assert len(_bin.imported_symbol_names) > 0, "Missing imported symbols"

    @abstractmethod
    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_resolved_imported_symbols(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported symbols correspond to a symbol object."""
        ...


class TestFSMapper(BaseTestFsMapper):
    """Main functional test class for the FS mapper. Tests are done from the CLI."""

    SUBCOMMAND = "fs"  # type: ignore

    # =============================== FIXTURES ========================================

    @pytest.fixture(scope="class")
    def export_res(self, tmp_path_factory, request) -> BaseTestFsMapper.ExecResults:
        """Run Pyrrha with export activated."""
        runner = CliRunner()
        tmp_path = (
            tmp_path_factory.mktemp("db", numbered=True)
            / f"{self.SUBCOMMAND}-{request.param}-export.srctrlprj"
        )
        args = [
            self.SUBCOMMAND,
            "-e",
            "--db",
            f"{tmp_path}",
            "-j",
            request.param,
            f"{self.FW_TEST_PATH}",
        ]
        return self.ExecResults(res=runner.invoke(self.COMMAND, args), db_path=tmp_path)
    
    # =================================== TESTS ========================================

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize(
        "bin_path", BaseTestFsMapper.FW_TEST_BIN_PATHS, ids=BaseTestFsMapper._path_id
    )
    def test_resolved_imported_symbols(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported symbols correspond to a symbol object."""
        _bin = export_dump.get_binary_by_path(bin_path)
        for name in _bin.imported_symbol_names:
            assert isinstance(_bin.get_imported_symbol(name), Symbol), (
                "Some imported symbols have not been resolved"
            )


class TestFsCgMapper(BaseTestFsMapper):
    """Main functional test class for the fs-cg mapper. Tests are done from the CLI."""

    SUBCOMMAND = "fs-cg"  # type: ignore

    # =============================== INTERNAL STUFFS ==================================

    class ExecResults(BaseTestFsMapper.ExecResults):  # noqa: D106
        @property
        def export_path(self) -> Path:  # noqa: D102
            return self.db_path.with_suffix(InterImageCGMapper.FS_EXT)

    # =============================== FIXTURES =========================================

    @pytest.fixture(scope="class")
    def export_res(self, tmp_path_factory, request) -> BaseTestFsMapper.ExecResults:
        """Run Pyrrha with export activated."""
        runner = CliRunner()
        tmp_path = (
            tmp_path_factory.mktemp("db", numbered=True)
            / f"{self.SUBCOMMAND}-{request.param}-export.srctrlprj"
        )
        args = [
            self.SUBCOMMAND,
            "--db",
            f"{tmp_path}",
            "-j",
            request.param,
            f"{self.FW_TEST_PATH}",
        ]
        return self.ExecResults(res=runner.invoke(self.COMMAND, args), db_path=tmp_path)
    
    # =================================== TESTS ========================================

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize(
        "bin_path", BaseTestFsMapper.FW_TEST_BIN_PATHS, ids=BaseTestFsMapper._path_id
    )
    def test_plt_erasing(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported symbols are directly used (not through __imp_* functions)."""
        _bin = export_dump.get_binary_by_path(bin_path)
        trampoline = [
            f.name for f in filter(lambda f: f.name.startswith("__imp_"), _bin.iter_functions())
        ]
        assert not trampoline, f"__imp_* functions: {trampoline}"

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize(
        "bin_path", BaseTestFsMapper.FW_TEST_BIN_PATHS, ids=BaseTestFsMapper._path_id
    )
    def test_resolved_imported_symbols(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported symbols correspond to a symbol object."""
        _bin = export_dump.get_binary_by_path(bin_path)
        for func in _bin.iter_functions():
            for target in _bin.get_calls_from(func):
                if not _bin.function_exists(target.name):
                    assert target.name in _bin.imported_symbol_names
                    assert _bin.imported_symbol_exists(target.name)
                    assert isinstance(_bin.get_imported_symbol(target.name), Symbol)
