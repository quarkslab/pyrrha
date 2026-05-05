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
"""CLI Module."""

import functools
import logging
import multiprocessing
from pathlib import Path

import click
import coloredlogs  # type: ignore # no typing used in this library
from numbat import SourcetrailDB

from pyrrha_mapper import fs, intercg, exedecomp
from pyrrha_mapper.common import FileSystem
from pyrrha_mapper.types import Backend, ResolveDuplicateOption

# -------------------------------------------------------------------------------
#                           Shared option decorators
# -------------------------------------------------------------------------------


def resolve_duplicates_options(f):
    """Add the three mutually exclusive resolve-duplicate options (decorator)."""

    @click.option(
        "--ignore",
        "resolve_duplicates",
        flag_value=ResolveDuplicateOption.IGNORE,
        help="When resolving duplicate imports, ignore them.",
        default=True,
    )
    @click.option(
        "--arbitrary",
        "resolve_duplicates",
        flag_value=ResolveDuplicateOption.ARBITRARY,
        help="When resolving duplicate imports, select the first one available.",
    )
    @click.option(
        "--interactive",
        "resolve_duplicates",
        flag_value=ResolveDuplicateOption.INTERACTIVE,
        help="When resolving duplicate imports, user manually selects which one to use.",
    )
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


def jobs_option(max_fraction: float = 1.0):
    """Add a ``--jobs`` option (decorator).

    :param max_fraction: fraction of CPU count to use as the upper bound (default 1.0).
    """

    def decorator(f):
        max_jobs = max(1, int(multiprocessing.cpu_count() * max_fraction))

        @click.option(
            "-j",
            "--jobs",
            help="Number of parallel jobs.",
            type=click.IntRange(1, max_jobs, clamp=True),
            metavar="INT",
            default=1,
            show_default=True,
        )
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapper

    return decorator


def backend_option(f):
    """*Add the ``--backend`` option."""

    @click.option(
        "-b",
        "--backend",
        required=False,
        type=click.Choice([Backend.IDA, Backend.GHIDRA], case_sensitive=False),
        default=Backend.IDA,
        show_default=True,
        help="Backend to use.",
    )
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


def root_directory_argument(f):
    """Add the ``root_directory`` argument (decorator)."""

    @click.argument(
        "root_directory",
        type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    )
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


# -------------------------------------------------------------------------------
#                           Common command helpers
# -------------------------------------------------------------------------------


class MapperCommand(click.Command):
    """Common class to add shared options for mapper.

    Code from: https://stackoverflow.com/a/53875557
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.insert(
            0,
            click.core.Option(
                ("--db",),
                help=f"NumbatUI DB file path ({SourcetrailDB.SOURCETRAIL_DB_EXT}).",
                type=click.Path(file_okay=True, dir_okay=True, path_type=Path),
                default=Path() / f"{self.name}{SourcetrailDB.SOURCETRAIL_DB_EXT}",
                show_default=True,
            ),
        )
        self.params.insert(
            0,
            click.core.Option(("-d", "--debug"), is_flag=True, help="Set log level to DEBUG."),
        )
        self.no_args_is_help = True


def setup_logs(is_debug_level: bool, db_path: Path | None = None) -> None:
    """Set up coloured console logging and an optional log file.

    :param is_debug_level: if True, set the log level to DEBUG, else INFO.
    :param db_path: if provided, write a collocated ``.log`` file.
    """
    log_format = dict(fmt="[%(asctime)s][%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    level = logging.DEBUG if is_debug_level else logging.INFO
    coloredlogs.install(
        level=level,
        level_styles={
            "debug": {"color": "magenta"},
            "info": {"color": "cyan"},
            "warning": {"color": "yellow"},
            "error": {"color": "red"},
            "critical": {"bold": True, "color": "red"},
        },
        field_styles={"asctime": {"color": "green"}, "levelname": {"bold": True}},
        **log_format,
    )
    if db_path:
        handler = logging.FileHandler(db_path.with_suffix(".log"), mode="w")
        handler.setLevel(level)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.root.addHandler(handler)


def setup_db(db_path: Path, overwrite_db: bool = True) -> SourcetrailDB:
    """Create and/or open the corresponding Sourcetrail DB.

    :param db_path: path of the db to open/create
    :param overwrite_db: if the path corresponds to an existing db, if True, it will be
        cleared else not
    :return: the created or opened Sourcetrail DB
    """
    if SourcetrailDB.exists(db_path):
        return SourcetrailDB.open(db_path, clear=overwrite_db)
    path = Path(db_path)
    if path.suffix != SourcetrailDB.SOURCETRAIL_DB_EXT:
        path = path.with_suffix(f"{path.suffix}{SourcetrailDB.SOURCETRAIL_DB_EXT}")
    return SourcetrailDB.create(path)


# -------------------------------------------------------------------------------
#                           CLI
# -------------------------------------------------------------------------------

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=120)


@click.group(
    context_settings=CONTEXT_SETTINGS,
    help="Mapper collection for firmware analysis.",
    no_args_is_help=True,
)
def pyrrha():  # noqa: D103
    pass


@pyrrha.command(
    "fs",
    cls=MapperCommand,
    short_help="Map PE and ELF files of a filesystem into a NumbatUI-compatible db.",
    help=(
        "Map a filesystem into a NumbatUI-compatible db. "
        "It maps ELF and PE files, their imports/exports, "
        "plus the symlinks that point to these executable files."
    ),
)
@click.option(
    "-e",
    "--export",
    help="Create a JSON export of the resulting FileSystem mapping.",
    is_flag=True,
    default=False,
)
@jobs_option(max_fraction=1.0)
@resolve_duplicates_options
@root_directory_argument
def fs_mapper(
    debug: bool,
    db: Path,
    export: bool,
    jobs: int,
    resolve_duplicates: ResolveDuplicateOption,
    root_directory: Path,
):
    """Map PE and ELF files of a filesystem."""
    setup_logs(debug)
    db_instance = setup_db(db)
    root_directory = root_directory.absolute()

    filesystem = fs.FileSystemImportsMapper(root_directory, db_instance).map(
        jobs, resolve_duplicates
    )

    if export:
        filesystem.write(db_instance.path.with_suffix(".json"))

    db_instance.close()


@pyrrha.command(
    "fs-cg",
    cls=MapperCommand,
    short_help="Map the call graph of every firmware executable into a NumbatUI db.",
    help=(
        "Map the inter-image call graph of a whole filesystem into a NumbatUI db. "
        "It disassembles executables, extracts the call graph, "
        "and resolves all call references across binaries."
    ),
)
@jobs_option(max_fraction=0.7)
@resolve_duplicates_options
@backend_option
@root_directory_argument
def fs_call_graph_mapper(
    debug: bool,
    db: Path,
    jobs: int,
    resolve_duplicates: ResolveDuplicateOption,
    backend: Backend,
    root_directory: Path,
):
    """Map the inter-image call graph of a firmware filesystem."""
    setup_logs(debug, db)
    db_instance = setup_db(db)

    if backend not in (
        Backend.IDA,
        Backend.GHIDRA,
    ):
        click.echo("Backend not yet supported")
        return 1

    root_directory = root_directory.absolute()

    try:
        intercg_mapper = intercg.InterImageCGMapper(root_directory, db_instance, backend)
        fs_object: FileSystem = intercg_mapper.map(jobs, resolve_duplicates)
        fs_object.write(db_instance.path.with_suffix(intercg_mapper.FS_EXT))
    except RuntimeError:
        pass

    db_instance.commit()
    db_instance.close()


@pyrrha.command(
    "decomp",
    cls=MapperCommand,
    short_help="Map an executable call graph with its decompiled code.",
    help=(
        "Map a single executable call graph into a NumbatUI-compatible database. "
        "Also indexes the decompiled code along with all call cross-references."
    ),
)
@backend_option
@click.argument(
    "executable",
    type=click.Path(exists=False, file_okay=True, dir_okay=False, path_type=Path),
)
def fs_exe_decompiled_mapper(
    debug: bool,
    db: Path,
    backend: Backend,
    executable: Path,
):
    """Map a single executable with decompiled code."""
    if db.name == "decomp.srctrldb":
        db = Path(str(executable) + ".srctrldb")

    setup_logs(debug, db)
    db_instance = setup_db(db)

    match backend:
        case Backend.IDA:
            mapper = exedecomp.IdaDecompilMapper(db_instance, executable)
        case Backend.GHIDRA:
            mapper = exedecomp.GhidraDecompilMapper(db_instance, executable)
        case _:
            click.echo(f"Backend {backend.name} not yet supported")
            return 1

    if mapper.map():
        logging.info("success.")
    else:
        logging.error("failure.")

    logging.info(f"write db into: {db_instance.path}")
    db_instance.commit()
    db_instance.close()


if __name__ == "__main__":
    pyrrha()
