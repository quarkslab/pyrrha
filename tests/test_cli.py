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

import pytest
from click import BaseCommand
from click.testing import CliRunner, Result

from pyrrha_mapper.__main__ import pyrrha
from pyrrha_mapper.common import FileSystem


class TestCLI:
    """Tests to check that the CLI works and display correct messages."""

    COMMAND: BaseCommand = pyrrha
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

    @pytest.fixture(scope="class")
    def db_path(self, tmp_path_factory) -> Path:
        """Generate the path for DB file."""
        tmp = tmp_path_factory.mktemp("db", numbered=True)
        return tmp / f"test-{self.SUBCOMMAND}.srctrlprj"

    @pytest.mark.parametrize("nb_thread", [1, 16])
    def test_numbat_project_creation(self, nb_thread, db_path):
        """Two files are generated with correct extensions."""
        runner = CliRunner()
        args = [
            self.SUBCOMMAND,
            "--db",
            f"{db_path}",
            "-j",
            nb_thread,
            f"{self.FW_TEST_PATH}",
        ]
        res = runner.invoke(self.COMMAND, args)
        assert res.exit_code == 0
        assert db_path.exists()
        assert db_path.with_suffix(".srctrldb").exists(), "Missing DB file"
        assert db_path.with_suffix(".srctrlprj").exists(), "Missing project file"

    @pytest.fixture
    def export_path(self, db_path: Path) -> Path:
        """Compute path for the exported JSON."""
        return db_path.with_suffix(".json")

    @abstractmethod
    @pytest.fixture(params=[1, 16])
    def export_res(self, db_path: Path, request) -> Result:
        """Run Pyrrha with export activated."""
        pass

    def test_export_creation(self, export_res: Result, export_path: Path) -> None:
        """Export file exist."""
        assert export_res.exit_code == 0
        assert export_path.exists(), "Export file does not exist"

    @pytest.fixture
    def export_dump(self, export_res, export_path: Path) -> FileSystem:
        """Load JSON export into a FileSystem object."""
        return FileSystem.from_json_export(export_path)

    def test_export_format(self, export_dump: FileSystem) -> None:
        """JSON export is loaded as a Filesystem object."""
        assert isinstance(export_dump, FileSystem), "Export cannot be loaded correctly"

    def test_binary_list(self, export_dump: FileSystem) -> None:
        """Firmware binaries are present in results."""
        assert {
            _bin.path for _bin in export_dump.iter_binaries()
        } == self.FW_TEST_BIN_PATHS, "Missing binaries"

    def test_symlink_list(self, export_dump: FileSystem) -> None:
        """Firmware symlinks are present in results."""
        assert {
            sym.path for sym in export_dump.iter_symlinks()
        } == self.FW_TEST_SYMLINKS_PATHS, "Missing symlinks"

    @staticmethod
    def _path_id(val):
        if isinstance(val, Path):
            return str(val)
        return val

    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_exported_symbols(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Exported symbols exist for each binary of the firware."""
        _bin = export_dump.get_binary_by_path(bin_path)
        assert len(list(_bin.iter_exported_symbols())) > 0, "Missing exported symbols"

    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_dependencies(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported libraries exist for each binary of the firware except ldd."""
        _bin = export_dump.get_binary_by_path(bin_path)
        if bin_path == self.FW_TEST_LD:
            assert len(list(_bin.iter_imported_libraries())) == 0, (
                "Create false imported libraries"
            )
        else:
            assert len(list(_bin.iter_imported_libraries())) > 0, (
                "Missing imported libraries"
            )

    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_resolved_dependencies(
        self, bin_path: Path, export_dump: FileSystem
    ) -> None:
        """Imported libraries correspond to a binary object."""
        _bin = export_dump.get_binary_by_path(bin_path)
        assert len(list(_bin.iter_imported_libraries())) == len(
            _bin.imported_library_names
        ), "Some imported libraries have not been resolved"

    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_imported_symbols(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported symbols exist for each binary of the firware except ldd."""
        _bin = export_dump.get_binary_by_path(bin_path)
        if bin_path == self.FW_TEST_LD:
            assert len(_bin.imported_symbol_names) == 0, "Create false imported symbols"
        else:
            assert len(_bin.imported_symbol_names) > 0, "Missing imported symbols"

    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS, ids=_path_id)
    def test_resolved_imported_symbols(
        self, bin_path: Path, export_dump: FileSystem
    ) -> None:
        """Imported symbols correspond to a symbol object."""
        _bin = export_dump.get_binary_by_path(bin_path)
        assert len(list(_bin.iter_imported_symbols())) == len(
            _bin.imported_symbol_names
        ), "Some imported symbols have not been resolved"


class TestFSMapper(BaseTestFsMapper):
    """Main functional test class for the FS mapper. Tests are done from the CLI."""

    SUBCOMMAND = "fs"  # type: ignore

    @pytest.fixture(params=[1, 16])
    def export_res(self, db_path: Path, request) -> Result:
        """Run Pyrrha with export activated."""
        runner = CliRunner()
        args = [
            self.SUBCOMMAND,
            "-e",
            "--db",
            f"{db_path}",
            "-j",
            request.param,
            f"{self.FW_TEST_PATH}",
        ]
        res = runner.invoke(self.COMMAND, args)
        return res


class TestFsCgMapper(BaseTestFsMapper):
    """Main functional test class for the fs-cg mapper. Tests are done from the CLI."""

    SUBCOMMAND = "fs-cg"  # type: ignore

    @pytest.fixture
    def export_path(self, db_path: Path) -> Path:
        """Compute path for the exported JSON."""
        return db_path.with_suffix(".bins.json")

    @pytest.fixture(params=[1, 16], scope="class")
    def export_res(self, db_path: Path, request) -> Result:
        """Run Pyrrha with export activated."""
        runner = CliRunner()
        args = [
            self.SUBCOMMAND,
            "--db",
            f"{db_path}",
            "-j",
            request.param,
            f"{self.FW_TEST_PATH}",
        ]
        res = runner.invoke(self.COMMAND, args)
        return res
