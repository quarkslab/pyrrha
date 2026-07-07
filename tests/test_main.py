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
"""Unit tests for the CLI wiring of :mod:`pyrrha_mapper.__main__`.

These tests drive the Click commands with :class:`CliRunner` while replacing
the mapper classes, the database factory and the logging setup with fakes.
No disassembler backend, numbat database or firmware file is touched: only the
argument parsing, command dispatch and orchestration of ``__main__`` is
exercised.
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrrha_mapper import __main__ as main
from pyrrha_mapper.types import Backend, ResolveDuplicateOption

# Captured before any fixture stubs it out, so the setup_logs / setup_db tests
# can run the real implementations.
_REAL_SETUP_LOGS = main.setup_logs
_REAL_SETUP_DB = main.setup_db


# --------------------------------------------------------------------------- #
#  Fakes
# --------------------------------------------------------------------------- #


class FakeDB:
    """Minimal stand-in for an opened SourcetrailDB instance."""

    SOURCETRAIL_DB_EXT = ".srctrldb"

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.committed = False
        self.closed = False

    def commit(self) -> None:  # noqa: D102
        self.committed = True

    def close(self) -> None:  # noqa: D102
        self.closed = True


class FakeFileSystem:
    """Stand-in for the FileSystem object returned by the imports mapper."""

    def __init__(self) -> None:
        self.written_to: list[Path] = []

    def write(self, path: Path) -> None:  # noqa: D102
        self.written_to.append(Path(path))


class FakeImportsMapper:
    """Stand-in for FileSystemImportsMapper recording its constructor/map args."""

    instances: list["FakeImportsMapper"] = []

    def __init__(self, root_directory: Path, db) -> None:
        self.root_directory = root_directory
        self.db = db
        self.map_args: tuple | None = None
        self.fs = FakeFileSystem()
        FakeImportsMapper.instances.append(self)

    def map(self, jobs: int, resolve_duplicates: ResolveDuplicateOption) -> FakeFileSystem:  # noqa: D102
        self.map_args = (jobs, resolve_duplicates)
        return self.fs


class FakeInterCGMapper:
    """Stand-in for InterImageCGMapper."""

    FS_EXT = ".pyrrha"
    instances: list["FakeInterCGMapper"] = []
    raise_runtime = False

    def __init__(self, root_directory: Path, db, backend: Backend) -> None:
        self.root_directory = root_directory
        self.db = db
        self.backend = backend
        self.map_args: tuple | None = None
        self.fs = FakeFileSystem()
        FakeInterCGMapper.instances.append(self)

    def map(self, jobs: int, resolve_duplicates: ResolveDuplicateOption) -> FakeFileSystem:  # noqa: D102
        if FakeInterCGMapper.raise_runtime:
            raise RuntimeError("boom")
        self.map_args = (jobs, resolve_duplicates)
        return self.fs


class FakeExport:
    """Stand-in for the export object returned by DecompilMapper.to_export."""

    def __init__(self) -> None:
        self.written_to: list[Path] = []

    def write(self, path: Path) -> None:  # noqa: D102
        self.written_to.append(Path(path))


class FakeDecompMapper:
    """Stand-in for IdaDecompilMapper / GhidraDecompilMapper."""

    instances: list["FakeDecompMapper"] = []
    map_returns = True

    def __init__(self, db, executable: Path) -> None:
        self.db = db
        self.executable = executable
        self.export = FakeExport()
        FakeDecompMapper.instances.append(self)

    def map(self) -> bool:  # noqa: D102
        return FakeDecompMapper.map_returns

    def to_export(self) -> FakeExport:  # noqa: D102
        return self.export


@pytest.fixture(autouse=True)
def _patch_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace heavy collaborators with fakes and reset their recorded state."""
    FakeImportsMapper.instances.clear()
    FakeInterCGMapper.instances.clear()
    FakeInterCGMapper.raise_runtime = False
    FakeDecompMapper.instances.clear()
    FakeDecompMapper.map_returns = True

    created: list[FakeDB] = []

    def fake_setup_db(db_path: Path, overwrite_db: bool = True) -> FakeDB:
        inst = FakeDB(db_path)
        created.append(inst)
        return inst

    monkeypatch.setattr(main, "setup_db", fake_setup_db)
    # Avoid touching the global logging configuration / writing .log files.
    monkeypatch.setattr(main, "setup_logs", lambda *a, **k: None)
    monkeypatch.setattr(main, "FileSystemImportsMapper", FakeImportsMapper)
    monkeypatch.setattr(main, "InterImageCGMapper", FakeInterCGMapper)
    monkeypatch.setattr(main, "IdaDecompilMapper", FakeDecompMapper)
    monkeypatch.setattr(main, "GhidraDecompilMapper", FakeDecompMapper)


@pytest.fixture
def runner() -> CliRunner:
    """Return a Click CliRunner (stderr is captured separately by default)."""
    return CliRunner()


# --------------------------------------------------------------------------- #
#  Group / help
# --------------------------------------------------------------------------- #


class TestGroup:
    """Tests for the top-level pyrrha group."""

    def test_no_args_shows_help(self, runner: CliRunner) -> None:
        """Invoking pyrrha with no arguments prints help (Click exits with code 2)."""
        res = runner.invoke(main.pyrrha, [])
        assert res.exit_code == 2  # no_args_is_help on a group
        assert "Mapper collection for firmware analysis." in res.output

    def test_help_lists_subcommands(self, runner: CliRunner) -> None:
        """The help output lists the three mapper subcommands."""
        res = runner.invoke(main.pyrrha, ["--help"])
        assert res.exit_code == 0
        for cmd in ("fs", "fs-cg", "decomp"):
            assert cmd in res.output


# --------------------------------------------------------------------------- #
#  setup_db helper
# --------------------------------------------------------------------------- #


class TestSetupDB:
    """Tests for the setup_db helper (real implementation, fake numbat)."""

    def test_opens_existing_db(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An existing db path is opened (and cleared when overwrite is True)."""
        calls: dict = {}

        class StubDB:
            SOURCETRAIL_DB_EXT = ".srctrldb"

            @staticmethod
            def exists(path):
                return True

            @staticmethod
            def open(path, clear):
                calls["open"] = (path, clear)
                return "opened"

            @staticmethod
            def create(path):
                calls["create"] = path
                return "created"

        monkeypatch.setattr(main, "SourcetrailDB", StubDB)
        result = _REAL_SETUP_DB(Path("/tmp/x.srctrldb"), overwrite_db=True)
        assert result == "opened"
        assert calls["open"] == (Path("/tmp/x.srctrldb"), True)

    def test_creates_db_and_fixes_suffix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-existing path without the db suffix gets the suffix appended."""
        calls: dict = {}

        class StubDB:
            SOURCETRAIL_DB_EXT = ".srctrldb"

            @staticmethod
            def exists(path):
                return False

            @staticmethod
            def open(path, clear):  # pragma: no cover - not taken here
                raise AssertionError

            @staticmethod
            def create(path):
                calls["create"] = Path(path)
                return "created"

        monkeypatch.setattr(main, "SourcetrailDB", StubDB)
        result = _REAL_SETUP_DB(Path("/tmp/mydb"))
        assert result == "created"
        assert calls["create"] == Path("/tmp/mydb.srctrldb")


# --------------------------------------------------------------------------- #
#  fs command
# --------------------------------------------------------------------------- #


class TestFsCommand:
    """Tests for the ``fs`` (filesystem imports) command."""

    def test_runs_mapper_and_closes_db(self, runner: CliRunner, tmp_path: Path) -> None:
        """Fs builds the imports mapper, runs map() and closes the db."""
        res = runner.invoke(main.pyrrha, ["fs", str(tmp_path)])
        assert res.exit_code == 0, res.output
        assert len(FakeImportsMapper.instances) == 1
        mapper = FakeImportsMapper.instances[0]
        # Default jobs is 1, default resolve is IGNORE.
        assert mapper.map_args == (1, ResolveDuplicateOption.IGNORE)
        # root_directory is resolved to an absolute path.
        assert mapper.root_directory.is_absolute()
        assert mapper.db.closed is True
        # No export requested -> nothing written.
        assert mapper.fs.written_to == []

    def test_export_flag_writes_json(self, runner: CliRunner, tmp_path: Path) -> None:
        """The --export flag writes a JSON sibling of the db."""
        db_path = tmp_path / "out.srctrldb"
        res = runner.invoke(main.pyrrha, ["fs", "--db", str(db_path), "--export", str(tmp_path)])
        assert res.exit_code == 0, res.output
        mapper = FakeImportsMapper.instances[0]
        assert mapper.fs.written_to == [db_path.with_suffix(".json")]

    def test_arbitrary_resolve_and_jobs(self, runner: CliRunner, tmp_path: Path) -> None:
        """--arbitrary and -j are forwarded to map()."""
        res = runner.invoke(main.pyrrha, ["fs", "--arbitrary", "-j", "1", str(tmp_path)])
        assert res.exit_code == 0, res.output
        mapper = FakeImportsMapper.instances[0]
        assert mapper.map_args == (1, ResolveDuplicateOption.ARBITRARY)

    def test_missing_directory_errors(self, runner: CliRunner) -> None:
        """A non-existent root_directory is rejected by Click."""
        res = runner.invoke(main.pyrrha, ["fs", "/does/not/exist"])
        assert res.exit_code != 0
        assert len(FakeImportsMapper.instances) == 0


# --------------------------------------------------------------------------- #
#  fs-cg command
# --------------------------------------------------------------------------- #


class TestFsCgCommand:
    """Tests for the ``fs-cg`` (inter-image call graph) command."""

    def test_runs_and_writes_fs(self, runner: CliRunner, tmp_path: Path) -> None:
        """fs-cg runs the mapper, writes the FS export and commits/closes the db."""
        db_path = tmp_path / "cg.srctrldb"
        res = runner.invoke(main.pyrrha, ["fs-cg", "--db", str(db_path), str(tmp_path)])
        assert res.exit_code == 0, res.output
        assert len(FakeInterCGMapper.instances) == 1
        mapper = FakeInterCGMapper.instances[0]
        assert mapper.backend == Backend.IDA  # default backend
        assert mapper.fs.written_to == [db_path.with_suffix(FakeInterCGMapper.FS_EXT)]
        assert mapper.db.committed is True
        assert mapper.db.closed is True

    def test_ghidra_backend_selected(self, runner: CliRunner, tmp_path: Path) -> None:
        """-b ghidra selects the Ghidra backend."""
        res = runner.invoke(main.pyrrha, ["fs-cg", "-b", "ghidra", str(tmp_path)])
        assert res.exit_code == 0, res.output
        assert FakeInterCGMapper.instances[0].backend == Backend.GHIDRA

    def test_runtime_error_is_swallowed(self, runner: CliRunner, tmp_path: Path) -> None:
        """A RuntimeError from map() is caught; the db is still committed/closed."""
        FakeInterCGMapper.raise_runtime = True
        res = runner.invoke(main.pyrrha, ["fs-cg", str(tmp_path)])
        assert res.exit_code == 0, res.output
        mapper = FakeInterCGMapper.instances[0]
        assert mapper.fs.written_to == []  # write skipped
        assert mapper.db.committed is True
        assert mapper.db.closed is True


# --------------------------------------------------------------------------- #
#  decomp command
# --------------------------------------------------------------------------- #


class TestDecompCommand:
    """Tests for the ``decomp`` (single executable) command."""

    def test_ida_default_runs_and_commits(self, runner: CliRunner, tmp_path: Path) -> None:
        """Decomp defaults to IDA, runs map(), then commits and closes the db."""
        exe = tmp_path / "prog"
        res = runner.invoke(main.pyrrha, ["decomp", str(exe)])
        assert res.exit_code == 0, res.output
        assert len(FakeDecompMapper.instances) == 1
        mapper = FakeDecompMapper.instances[0]
        assert mapper.executable == exe
        assert mapper.db.committed is True
        assert mapper.db.closed is True

    def test_default_db_path_derived_from_executable(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """With the default --db, the db path is derived from the executable."""
        exe = tmp_path / "prog"
        res = runner.invoke(main.pyrrha, ["decomp", str(exe)])
        assert res.exit_code == 0, res.output
        mapper = FakeDecompMapper.instances[0]
        assert mapper.db.path == Path(str(exe) + ".srctrldb")

    def test_export_writes_when_map_succeeds(self, runner: CliRunner, tmp_path: Path) -> None:
        """--export writes a JSON export only when mapping succeeds."""
        exe = tmp_path / "prog"
        res = runner.invoke(main.pyrrha, ["decomp", "--export", str(exe)])
        assert res.exit_code == 0, res.output
        mapper = FakeDecompMapper.instances[0]
        assert mapper.export.written_to == [mapper.db.path.with_suffix(".json")]

    def test_no_export_when_map_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        """When map() returns False, no export is written even with --export."""
        FakeDecompMapper.map_returns = False
        exe = tmp_path / "prog"
        res = runner.invoke(main.pyrrha, ["decomp", "--export", str(exe)])
        assert res.exit_code == 0, res.output
        mapper = FakeDecompMapper.instances[0]
        assert mapper.export.written_to == []

    def test_ghidra_backend_used(self, runner: CliRunner, tmp_path: Path) -> None:
        """-b ghidra instantiates the Ghidra decompile mapper."""
        exe = tmp_path / "prog"
        res = runner.invoke(main.pyrrha, ["decomp", "-b", "ghidra", str(exe)])
        assert res.exit_code == 0, res.output
        # Both Ida/Ghidra mappers are patched to the same fake; assert one ran.
        assert len(FakeDecompMapper.instances) == 1


# --------------------------------------------------------------------------- #
#  setup_logs helper
# --------------------------------------------------------------------------- #


class TestSetupLogs:
    """Tests for the setup_logs helper."""

    def test_console_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without a db_path, only the console logger is configured."""
        installed: dict = {}
        monkeypatch.setattr(main.coloredlogs, "install", lambda **kw: installed.update(kw))
        # Restore the real implementation (the autouse fixture stubbed it out).
        monkeypatch.setattr(main, "setup_logs", _REAL_SETUP_LOGS)
        main.setup_logs(is_debug_level=True)
        import logging

        assert installed["level"] == logging.DEBUG

    def test_debug_false_uses_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When not in debug mode the INFO level is used."""
        installed: dict = {}
        monkeypatch.setattr(main.coloredlogs, "install", lambda **kw: installed.update(kw))
        monkeypatch.setattr(main, "setup_logs", _REAL_SETUP_LOGS)
        main.setup_logs(is_debug_level=False)
        import logging

        assert installed["level"] == logging.INFO

    def test_with_db_path_adds_file_handler(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A db_path causes a collocated .log file handler to be added."""
        import logging

        monkeypatch.setattr(main.coloredlogs, "install", lambda **kw: None)
        monkeypatch.setattr(main, "setup_logs", _REAL_SETUP_LOGS)
        before = list(logging.root.handlers)
        db_path = tmp_path / "run.srctrldb"
        try:
            main.setup_logs(is_debug_level=False, db_path=db_path)
            added = [h for h in logging.root.handlers if h not in before]
            assert any(isinstance(h, logging.FileHandler) for h in added)
            assert (tmp_path / "run.log").exists()
        finally:
            for h in logging.root.handlers:
                if h not in before:
                    logging.root.removeHandler(h)
                    h.close()


# --------------------------------------------------------------------------- #
#  Unsupported-backend branches
#
#  Click's Choice only accepts ida/ghidra, so the "not yet supported" branches
#  are unreachable through normal CLI parsing. They are exercised by invoking
#  the command callbacks directly with an out-of-choice backend.
# --------------------------------------------------------------------------- #


class TestUnsupportedBackend:
    """Tests for the not-yet-supported backend guards."""

    def test_fs_cg_unsupported_backend_returns_1(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """fs-cg returns 1 and echoes a message for an unsupported backend."""
        messages: list[str] = []
        monkeypatch.setattr(main.click, "echo", lambda m: messages.append(m))
        callback = main.fs_call_graph_mapper.callback
        assert callback is not None
        rv = callback(
            debug=False,
            db=tmp_path / "cg.srctrldb",
            jobs=1,
            resolve_duplicates=ResolveDuplicateOption.IGNORE,
            backend=Backend.BINARY_NINJA,
            root_directory=tmp_path,
        )
        assert rv == 1
        assert messages == ["Backend not yet supported"]
        assert FakeInterCGMapper.instances == []

    def test_decomp_unsupported_backend_returns_1(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Decomp returns 1 and echoes a message for an unsupported backend."""
        messages: list[str] = []
        monkeypatch.setattr(main.click, "echo", lambda m: messages.append(m))
        callback = main.fs_exe_decompiled_mapper.callback
        assert callback is not None
        rv = callback(
            debug=False,
            db=tmp_path / "x.srctrldb",
            backend=Backend.BINARY_NINJA,
            export=False,
            executable=tmp_path / "prog",
        )
        assert rv == 1
        assert any("not yet supported" in m for m in messages)
        assert FakeDecompMapper.instances == []
