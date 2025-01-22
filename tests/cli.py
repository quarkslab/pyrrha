from pathlib import Path

import pytest
from click import BaseCommand
from click.testing import CliRunner, Result
from pyrrha_mapper import pyrrha
from pyrrha_mapper.mappers.intercg.pyrrha_dump import PyrrhaDump


class TestCLI:
    COMMAND: BaseCommand = pyrrha
    SUBCOMMANDS = pyrrha.commands

    def test_usage(self):
        runner = CliRunner()
        res_short = runner.invoke(self.COMMAND, ["-h"])
        res_long = runner.invoke(self.COMMAND, ["--help"])
        for res in [res_long, res_short]:
            assert res.exit_code == 0
            assert res.output.startswith(f"Usage: {self.COMMAND.name}")
        assert res_short.output == res_long.output

    @pytest.mark.parametrize("subcommand", SUBCOMMANDS)
    def test_subcommand_usage(self, subcommand: str):
        runner = CliRunner()
        res_short = runner.invoke(self.COMMAND, [subcommand, "-h"])
        res_long = runner.invoke(self.COMMAND, [subcommand, "--help"])
        for res in [res_long, res_short]:
            assert res.exit_code == 0
            assert res.output.startswith(f"Usage: {self.COMMAND.name} {subcommand}")
        assert res_short.output == res_long.output


class TestFSMapper:
    COMMAND = pyrrha
    SUBCOMMAND = "fs"
    FW_TEST_PATH = Path(__file__).parent / "test_fw"
    FW_TEST_LD = "/lib/ld-linux.so.3"
    FW_TEST_BIN_PATHS = {
        FW_TEST_LD,
        "/lib/libc.so.6",
        "/lib/libcrypto.so.1.1",
        "/lib/libdl.so.2",
        "/lib/libpthread.so.0",
        "/lib/libssl.so.1.1",
        "/bin/openssl",
    }
    FW_TEST_SYMLINKS_PATHS = {"/lib/libssl.so"}

    @pytest.fixture
    def db_path(self, tmp_path_factory) -> Path:
        tmp = tmp_path_factory.mktemp("db", numbered=True)
        return tmp / "test.srctrlprj"

    @pytest.mark.parametrize("nb_thread", [1, 16])
    def test_numbat_project_creation(self, nb_thread, db_path):
        runner = CliRunner()
        args = [self.SUBCOMMAND, "--db", f"{db_path}", "-j", nb_thread, f"{self.FW_TEST_PATH}"]
        res = runner.invoke(self.COMMAND, args)
        assert res.exit_code == 0
        assert db_path.exists()
        assert db_path.with_suffix(".srctrldb").exists()

    @pytest.fixture
    def export_path(self, db_path: Path) -> Path:
        return db_path.with_suffix(".json")

    @pytest.fixture(params=[1, 16])
    def export_res(self, db_path: Path, request) -> Result:
        runner = CliRunner()
        args = [self.SUBCOMMAND, "-e", "--db", f"{db_path}", "-j", request.param, f"{self.FW_TEST_PATH}"]
        res = runner.invoke(self.COMMAND, args)
        return res

    def test_export_creation(self, export_res: Result, export_path: Path) -> None:
        assert export_res.exit_code == 0
        assert export_path.exists()

    @pytest.fixture
    def export_dump(self, export_res, export_path: Path) -> PyrrhaDump:
        return PyrrhaDump(export_path)

    def test_export_format(self, export_dump: PyrrhaDump) -> None:
        assert isinstance(export_dump, PyrrhaDump)

    def test_binary_list(self, export_dump: PyrrhaDump) -> None:
        assert set(export_dump.bin_by_path.keys()) == self.FW_TEST_BIN_PATHS

    def test_symlink_list(self, export_dump: PyrrhaDump) -> None:
        assert set(export_dump.symlinks_by_path.keys()) == self.FW_TEST_SYMLINKS_PATHS

    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS)
    def test_exported_symbols(self, bin_path, export_dump) -> None:
        bin_id = export_dump.get_id(bin_path)
        assert len(export_dump.get_exported_symbols(bin_id)) > 0

    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS)
    def test_dependencies(self, bin_path, export_dump) -> None:
        bin_id = export_dump.get_id(bin_path)
        if bin_path == self.FW_TEST_LD:
            assert len(export_dump.get_dependencies(bin_id)) == 0
        else:
            assert len(export_dump.get_dependencies(bin_id)) > 0

    @pytest.mark.parametrize("bin_path", FW_TEST_BIN_PATHS)
    def test_imported_symbols(self, bin_path, export_dump) -> None:
        bin_id = export_dump.get_id(bin_path)
        if bin_path == self.FW_TEST_LD:
            assert len(export_dump.get_imported_symbols(bin_id)) == 0
        else:
            assert len(export_dump.get_imported_symbols(bin_id)) > 0
