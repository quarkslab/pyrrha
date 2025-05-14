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

import logging
import multiprocessing
from pathlib import Path

import click
import coloredlogs  # type: ignore # no typing used in this library
from numbat import SourcetrailDB

from pyrrha_mapper import exedecomp, fs, intercg
from pyrrha_mapper.common import FileSystem
from pyrrha_mapper.types import Disassembler, Exporters, ResolveDuplicateOption

# -------------------------------------------------------------------------------
#                           Common stuff for mappers
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
                help="NumbatUI DB file path (.srctrldb).",
                type=click.Path(file_okay=True, dir_okay=True, path_type=Path),
                default=Path() / f"{self.name}.srctrldb",
                show_default=True,
            ),
        )
        self.params.insert(
            0,
            click.core.Option(("-d", "--debug"), is_flag=True, help="Set log level to DEBUG"),
        )
        self.no_args_is_help = True


def setup_logs(is_debug_level: bool, db_path: Path | None = None) -> None:
    """Set up logs.

    :param is_debug_level: if True set the log level as DEBUG else INFO
    :param db_path: if provided, save a collocated log file.
    """
    log_format = dict(
        fmt="[%(asctime)s][%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
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
        log_file = db_path.with_suffix(".log")
        # add file handler
        file_handler = logging.FileHandler(log_file, mode="w")
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.root.addHandler(file_handler)


def setup_db(db_path, overwrite_db: bool = True) -> SourcetrailDB:
    """Create and/or open the corresponding Sourcetrail DB.

    :param db_path: path of the db to open/create
    :param overwrite_db: if the path corresponds to an existing db, if True, it will be
        cleared else not
    :return: the created or opened Sourcetrail DB
    """
    # db creation/and or opening
    if SourcetrailDB.exists(db_path):
        db = SourcetrailDB.open(db_path, clear=overwrite_db)
    else:
        db = SourcetrailDB.create(db_path)
    return db


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


"""
 Filesystem mapper.
 Map ELF/PE files, their imports and their exports.
 Also map symlinks which target ELF/PE files.
"""


@pyrrha.command(
    "fs",
    cls=MapperCommand,
    short_help="Map PE and ELF files of a filesystem into a numbatui-compatible db.",
    help="Map a filesystem into a numbatui-compatible db. It maps ELF and PE files, \
their imports/exports plus the symlinks that points on these executable files.",
)
@click.option(
    "-e",
    "--export",
    help="Create an export of the resulting FileSystem mapping (in JSON).",
    is_flag=True,
    default=False,
    show_default=False,
)
@click.option(
    "-j",
    "--jobs",
    help="Number of parallel jobs created (threads).",
    type=click.IntRange(1, multiprocessing.cpu_count(), clamp=True),
    metavar="INT",
    default=1,
    show_default=True,
)
@click.option(
    "--ignore",
    "resolve_duplicates",
    flag_value=ResolveDuplicateOption.IGNORE,
    help="When resolving duplicate imports, ignore them",
    default=True,
)
@click.option(
    "--arbitrary",
    "resolve_duplicates",
    flag_value=ResolveDuplicateOption.ARBITRARY,
    help="When resolving duplicate imports, select the first one available",
)
@click.option(
    "--interactive",
    "resolve_duplicates",
    flag_value=ResolveDuplicateOption.INTERACTIVE,
    help="When resolving duplicate imports, user manually select which one to use",
)
@click.argument(
    "root_directory",
    # help='Path of the directory containing the filesystem to map.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def fs_mapper(# noqa: D103
    debug: bool,  
    db: Path,
    export: bool,
    jobs: int,
    resolve_duplicates: ResolveDuplicateOption,
    root_directory: Path,
):  # noqa: D103
    setup_logs(debug)
    db_instance = setup_db(db)

    root_directory = root_directory.absolute()
    fs_mapper = fs.FileSystemImportsMapper(root_directory, db_instance)

    filesystem = fs_mapper.map(jobs, resolve_duplicates)

    # if enabled export enabled, save FileSystem object in a JSON
    if export:
        # maybe in the future a user can choose the output path ?
        output_file = db_instance.path.with_suffix(".json")
        filesystem.write(output_file)

    db_instance.close()


@pyrrha.command(
    "fs-cg",
    cls=MapperCommand,
    short_help="Map the Call Graph of every firmware executable into  a NumbatUI db.",
    help="Map a the Inter-Image Call Graph of a whole filesystem into a NumbatUI db."
    "It disassembles executables using a disassembler and extract the call graph."
    "It then results all call references across binaries.",
)
@click.option(
    "-j",
    "--jobs",
    help="Number of parallel jobs created (threads).",
    type=click.IntRange(1, int(multiprocessing.cpu_count() * 0.7), clamp=True),  # 70% of threads
    metavar="INT",
    default=1,
    show_default=True,
)
@click.option(
    "--ignore",
    "resolve_duplicates",
    flag_value=ResolveDuplicateOption.IGNORE,
    help="When resolving duplicate imports, ignore them",
    default=True,
)
@click.option(
    "--arbitrary",
    "resolve_duplicates",
    flag_value=ResolveDuplicateOption.ARBITRARY,
    help="When resolving duplicate imports, select the first one available",
)
@click.option(
    "--interactive",
    "resolve_duplicates",
    flag_value=ResolveDuplicateOption.INTERACTIVE,
    help="When resolving duplicate imports, user manually select which one to use",
)
@click.option(
    "--disassembler",
    required=False,
    type=Disassembler,
    default=Disassembler.AUTO,
    show_default=True,
    help="Disassembler to use for disassembly.",
)
@click.option(
    "--exporter",
    required=False,
    type=Exporters,
    default=Exporters.AUTO,
    show_default=True,
    help="Binary exporter to use for binary analysis.",
)
@click.argument(
    "root_directory",
    # help='Path of the directory containing the filesystem to map.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def fs_call_graph_mapper(  # noqa: D103
    debug: bool,
    db: Path,
    jobs: int,
    resolve_duplicates: ResolveDuplicateOption,
    disassembler: Disassembler,
    exporter: Exporters,
    root_directory,
):
    setup_logs(debug, db)
    db_instance = setup_db(db)

    if disassembler not in [Disassembler.AUTO, Disassembler.IDA]:
        click.echo("disassembler not yet supported")
        # TODO: add support for other disassembler
        return 1

    if exporter not in [Exporters.AUTO, Exporters.QUOKKA]:
        click.echo(f"binary exporter: {exporter.name} not yet supported")
        # TODO: add support for other disassembler
        return 1

    root_directory = root_directory.absolute()

    # Create InterCG mapper and launch mapping
    try:
        intercg_mapper = intercg.InterImageCGMapper(root_directory, db_instance)
        fs_object: FileSystem = intercg_mapper.map(jobs, resolve_duplicates)

        # systematically save the FileSystem object (shall be enriched with calls)
        output_file = db_instance.path.with_suffix(intercg_mapper.FS_EXT)
        fs_object.write(output_file)

    except RuntimeError:
        pass

    db_instance.commit()
    db_instance.close()


@pyrrha.command(
    "exe-decomp",
    cls=MapperCommand,
    short_help="Map an executable call graph with its decompiled code.",
    help="Map a single executable call graph into a numbatui-compatible database."
    "It also index the decompiled code along with all call cross-references.",
)
@click.option(
    "--disassembler",
    required=False,
    type=Disassembler,
    default=Disassembler.AUTO,
    show_default=True,
    help="Disassembler to use for disassembly.",
)
@click.argument(
    "executable",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
)
def fs_exe_decompiled_mapper(  # noqa: D103
    debug: bool, db: Path, disassembler: Disassembler, executable: Path
):
    setup_logs(debug, db)
    db_instance = setup_db(db)

    if disassembler not in [Disassembler.AUTO, Disassembler.IDA]:
        click.echo("disassembler not yet supported")
        # TODO: add support for other disassembler (forward parameter to mapper)
        return 1

    if exedecomp.map_binary(db_instance, executable):
        logging.info("success.")
    else:
        logging.error("failure.")

    db_instance.commit()
    db_instance.close()


if __name__ == "__main__":
    pyrrha()
