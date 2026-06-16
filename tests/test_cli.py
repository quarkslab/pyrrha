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

from pyrrha_mapper import FileSystem, Symbol
from pyrrha_mapper.__main__ import pyrrha
from pyrrha_mapper.mappers import ExportedDecompilation, InterImageCGMapper


def check_click_result(res: Result) -> None:
    """Raise Assertion error if issue."""
    assert res.exit_code == 0, res.output
    assert not res.exception, res.exception
    for log in res.stderr.splitlines():
        assert "ERROR" not in log and "WARNING" not in log and "CRITICAL" not in log, (
            f"Error log: {log}"
        )


def check_click_result_allow_logs(res: Result) -> None:
    """Like check_click_result but tolerates per-function ERROR/WARNING logs.

    The decomp mapper legitimately logs warnings/errors for individual
    functions (e.g. a declaration not located in some decompiled body); these
    do not make the run fail. Only the exit code and absence of an exception
    are checked here, plus that no CRITICAL message was emitted.
    """
    assert res.exit_code == 0, res.output
    assert not res.exception, res.exception
    for log in res.stderr.splitlines():
        assert "CRITICAL" not in log, f"Critical log: {log}"


class _SubprocessResult(NamedTuple):
    """Mimic the subset of click ``Result`` used by ``check_click_result``.

    Backends that start a JVM (Ghidra via pyghidra/JPype) cannot be launched
    reliably with ``CliRunner.invoke``: it runs the command *in-process*, and
    starting the JVM inside the already-initialised pytest/coverage process
    aborts JVM start-up (surfacing as
    ``module '_jpype' has no attribute '_java_lang_Class'``).  Running pyrrha
    in a fresh subprocess - exactly how it is used in production and in the
    standalone CLI - avoids this entirely.
    """

    exit_code: int
    output: str
    stderr: str
    exception: BaseException | None = None


def run_pyrrha_subprocess(args: list) -> "_SubprocessResult":
    """Run the pyrrha CLI in a separate process and adapt the result.

    :param args: CLI arguments (without the leading ``pyrrha``).
    :return: a ``Result``-compatible object accepted by ``check_click_result``.
    """
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "pyrrha_mapper", *map(str, args)],
        capture_output=True,
        text=True,
    )
    return _SubprocessResult(
        exit_code=completed.returncode,
        output=completed.stdout + completed.stderr,
        stderr=completed.stderr,
        exception=None,
    )


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
            assert res.output.startswith(f"Usage: {self.COMMAND.name}")
            check_click_result(res)
        assert res_short.output == res_long.output, "Usage different with -h/--help"

    @pytest.mark.parametrize("subcommand", SUBCOMMANDS)
    def test_subcommand_usage(self, subcommand: str):
        """Display correctly submcommand usage."""
        runner = CliRunner()
        res_short = runner.invoke(self.COMMAND, [subcommand, "-h"])
        res_long = runner.invoke(self.COMMAND, [subcommand, "--help"])
        for res in [res_long, res_short]:
            assert res.output.startswith(f"Usage: {self.COMMAND.name} {subcommand}")
            check_click_result(res)
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
        # Path("/lib/libcrypto.so.1.1"),
        Path("/lib/libcrypto.so.FOR_SONAME_TESTING"),
        Path("/lib/libdl.so.2"),
        Path("/lib/libpthread.so.0"),
        Path("/lib/libssl.so.1.1"),
        Path("/bin/openssl"),
    }
    FW_TEST_SYMLINKS_PATHS = {Path("/lib/libssl.so")}

    FW_TEST_SONAMES = {
        "ld-linux.so.3": "ld-linux.so.3",
        "libcrypto.so.FOR_SONAME_TESTING": "libcrypto.so.1.1",
        "libdl.so.2": "libdl.so.2",
        "libpthread.so.0": "libpthread.so.0",
        "libssl.so.1.1": "libssl.so.1.1",
    }

    # =============================== INTERNAL STUFFS ==================================

    class ExecResults(NamedTuple):  # noqa: D106
        res: Result
        db_path: Path

        @property
        def project_path(self) -> Path:  # noqa: D102
            return self.db_path.with_suffix(".srctrlprj")

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
    @classmethod
    def pyrrha_exec(cls, request, tmp_path_factory) -> ExecResults:
        """Run pyrrha whith the given thread number and the given db path."""
        runner = CliRunner()
        tmp_path = (
            tmp_path_factory.mktemp("db", numbered=True)
            / f"{cls.SUBCOMMAND}-{request.param}.srctrldb"
        )
        args = [
            cls.SUBCOMMAND,
            "--db",
            f"{tmp_path}",
            "-j",
            request.param,
            f"{cls.FW_TEST_PATH}",
        ]
        return cls.ExecResults(res=runner.invoke(cls.COMMAND, args), db_path=tmp_path)

    @abstractmethod
    @pytest.fixture(scope="class")
    def export_res(self, tmp_path_factory, request) -> ExecResults:
        """Run Pyrrha with export activated."""
        ...

    @pytest.fixture(scope="class")
    @classmethod
    def export_dump(cls, export_res: ExecResults) -> FileSystem:
        """Load JSON export into a FileSystem object."""
        return FileSystem.from_json_export(export_res.export_path)

    # =================================== TESTS ========================================

    @pytest.mark.parametrize("pyrrha_exec", [1, 16], indirect=True)
    def test_numbat_project_creation(self, pyrrha_exec: ExecResults):
        """Two files are generated with correct extensions."""
        check_click_result(pyrrha_exec.res)
        assert pyrrha_exec.db_path.with_suffix(".srctrldb").exists(), "Missing DB file"
        assert pyrrha_exec.db_path.with_suffix(".srctrlprj").exists(), "Missing project file"

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    def test_export_creation(self, export_res: ExecResults) -> None:
        """Export file exist."""
        check_click_result(export_res.res)
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
    @classmethod
    def export_res(cls, tmp_path_factory, request) -> BaseTestFsMapper.ExecResults:
        """Run Pyrrha with export activated."""
        runner = CliRunner()
        tmp_path = (
            tmp_path_factory.mktemp("db", numbered=True)
            / f"{cls.SUBCOMMAND}-{request.param}-export.srctrldb"
        )
        args = [
            cls.SUBCOMMAND,
            "-e",
            "--db",
            f"{tmp_path}",
            "-j",
            request.param,
            f"{cls.FW_TEST_PATH}",
        ]
        return cls.ExecResults(res=runner.invoke(cls.COMMAND, args), db_path=tmp_path)

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

    @pytest.mark.parametrize("export_res", [1, 16], indirect=True)
    @pytest.mark.parametrize(
        "bin_path", BaseTestFsMapper.FW_TEST_BIN_PATHS, ids=BaseTestFsMapper._path_id
    )
    def test_sonames(self, bin_path: Path, export_dump: FileSystem) -> None:
        """Imported symbols correspond to a symbol object."""
        _bin = export_dump.get_binary_by_path(bin_path)
        if _bin.path.name in BaseTestFsMapper.FW_TEST_SONAMES.keys():
            assert BaseTestFsMapper.FW_TEST_SONAMES[_bin.path.name] == _bin.soname, (
                "Some sonames are not matching"
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
    @classmethod
    def pyrrha_exec(cls, request, tmp_path_factory) -> BaseTestFsMapper.ExecResults:
        """Run pyrrha whith the given thread number and the given db path.

        Uses a subprocess (not CliRunner) because the Ghidra backend starts a
        JVM, which cannot be launched in-process inside pytest.
        """
        tmp_path = (
            tmp_path_factory.mktemp("db", numbered=True)
            / f"{cls.SUBCOMMAND}-{request.param}.srctrldb"
        )
        args = [
            cls.SUBCOMMAND,
            "--backend",
            f"{request.config.getoption('--backend')}",
            "--db",
            f"{tmp_path}",
            "-j",
            request.param,
            f"{cls.FW_TEST_PATH}",
        ]
        return cls.ExecResults(res=run_pyrrha_subprocess(args), db_path=tmp_path)

    @pytest.fixture(scope="class")
    @classmethod
    def export_res(cls, tmp_path_factory, request) -> BaseTestFsMapper.ExecResults:
        """Run Pyrrha with export activated.

        Uses a subprocess (not CliRunner) because the Ghidra backend starts a
        JVM, which cannot be launched in-process inside pytest.
        """
        tmp_path = (
            tmp_path_factory.mktemp("db", numbered=True)
            / f"{cls.SUBCOMMAND}-{request.param}-export.srctrldb"
        )
        args = [
            cls.SUBCOMMAND,
            "--backend",
            f"{request.config.getoption('--backend')}",
            "--db",
            f"{tmp_path}",
            "-j",
            request.param,
            f"{cls.FW_TEST_PATH}",
        ]
        return cls.ExecResults(res=run_pyrrha_subprocess(args), db_path=tmp_path)

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


class TestDecompMapper:
    """Functional tests for the decomp mapper. Tests are done from the CLI.

    The decomp mapper runs on a single executable, so each binary of the test
    firmware triggers its own ``decomp`` invocation. A subprocess (not
    CliRunner) is used because the Ghidra backend starts a JVM, which cannot be
    launched in-process inside pytest.
    """

    COMMAND: Command = pyrrha
    SUBCOMMAND = "decomp"

    FW_TEST_PATH = Path(__file__).parent / "test_fw"
    # Same set of executables as the fs-cg functional tests.
    FW_TEST_BIN_PATHS = BaseTestFsMapper.FW_TEST_BIN_PATHS

    class ExecResults(NamedTuple):  # noqa: D106
        res: Result
        db_path: Path

        @property
        def project_path(self) -> Path:  # noqa: D102
            return self.db_path.with_suffix(".srctrlprj")

        @property
        def export_path(self) -> Path:  # noqa: D102
            return self.db_path.with_suffix(".json")

    @staticmethod
    def _path_id(val):
        if isinstance(val, Path):
            return str(val)
        return val

    @classmethod
    def _host_path(cls, bin_path: Path) -> Path:
        """:return: the on-host path of a firmware-relative binary path."""
        return cls.FW_TEST_PATH / bin_path.relative_to(bin_path.anchor)

    # =============================== FIXTURES =========================================

    @pytest.fixture(scope="class")
    @classmethod
    def export_res(cls, tmp_path_factory, request) -> "TestDecompMapper.ExecResults":
        """Run the decomp mapper with export activated on a single executable."""
        bin_path: Path = request.param
        executable = cls._host_path(bin_path)
        tmp_path = (
            tmp_path_factory.mktemp("db", numbered=True)
            / f"{cls.SUBCOMMAND}-{bin_path.name}.srctrldb"
        )
        args = [
            cls.SUBCOMMAND,
            "--backend",
            f"{request.config.getoption('--backend')}",
            "--db",
            f"{tmp_path}",
            "--export",
            f"{executable}",
        ]
        return cls.ExecResults(res=run_pyrrha_subprocess(args), db_path=tmp_path)

    @pytest.fixture(scope="class")
    @classmethod
    def export_dump(cls, export_res: "TestDecompMapper.ExecResults") -> ExportedDecompilation:
        """Load the JSON export into an ExportedDecompilation object."""
        return ExportedDecompilation.from_json_export(export_res.export_path)

    # =================================== TESTS ========================================

    @pytest.mark.parametrize("export_res", FW_TEST_BIN_PATHS, indirect=True, ids=_path_id)
    def test_db_creation(self, export_res: "TestDecompMapper.ExecResults") -> None:
        """The NumbatUI DB and project files are generated."""
        check_click_result_allow_logs(export_res.res)
        assert export_res.db_path.with_suffix(".srctrldb").exists(), "Missing DB file"
        assert export_res.db_path.with_suffix(".srctrlprj").exists(), "Missing project file"

    @pytest.mark.parametrize("export_res", FW_TEST_BIN_PATHS, indirect=True, ids=_path_id)
    def test_export_creation(self, export_res: "TestDecompMapper.ExecResults") -> None:
        """The JSON export file exists."""
        check_click_result_allow_logs(export_res.res)
        assert export_res.export_path.exists(), "Export file does not exist"

    @pytest.mark.parametrize("export_res", FW_TEST_BIN_PATHS, indirect=True, ids=_path_id)
    def test_export_format(self, export_dump: ExportedDecompilation) -> None:
        """The JSON export loads as an ExportedDecompilation object."""
        assert isinstance(export_dump, ExportedDecompilation), "Export cannot be loaded correctly"

    @pytest.mark.parametrize("export_res", FW_TEST_BIN_PATHS, indirect=True, ids=_path_id)
    def test_functions_present(self, request, export_dump: ExportedDecompilation) -> None:
        """The export records functions and binds them to the analysed binary."""
        bin_path: Path = request.node.callspec.params["export_res"]
        assert export_dump.path.name == bin_path.name
        assert len(list(export_dump.iter_functions())) > 0, "No function recorded"

    @pytest.mark.parametrize("export_res", FW_TEST_BIN_PATHS, indirect=True, ids=_path_id)
    def test_function_addr_keys(self, export_dump: ExportedDecompilation) -> None:
        """Every function is stored under its own (parser-space) address."""
        for addr, func in export_dump.functions.items():
            assert func.addr == addr, (
                f"{func.name} stored under {addr:#x} but addr is {func.addr:#x}"
            )

    @pytest.mark.parametrize("export_res", FW_TEST_BIN_PATHS, indirect=True, ids=_path_id)
    def test_decompiled_source(self, export_dump: ExportedDecompilation) -> None:
        """At least one non-imported function carries decompiled source."""
        with_source = [f for f in export_dump.iter_functions() if f.type != "imported" and f.source]
        assert with_source, "No decompiled source recorded for any local function"
