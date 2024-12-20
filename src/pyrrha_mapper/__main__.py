# -*- coding: utf-8 -*-

#  Copyright 2023-2024 Quarkslab
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

import logging
import multiprocessing
from pathlib import Path

import click
import coloredlogs
from numbat import SourcetrailDB
from pyrrha_mapper.filesystem import ResolveDuplicateOption
from pyrrha_mapper.imports_mapper import FileSystemImportsMapper


# -------------------------------------------------------------------------------
#                           Common stuff for mappers
# -------------------------------------------------------------------------------


class MapperCommand(click.Command):
    """
    Common class to add shared options for mapper

    Code from: https://stackoverflow.com/a/53875557
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.insert(
            0,
            click.core.Option(
                ("--db",),
                help="Sourcetrail DB file path (.srctrldb).",
                type=click.Path(file_okay=True, dir_okay=True, path_type=Path),
                default=Path() / "pyrrha.srctrldb",
                show_default=True,
            ),
        )
        self.params.insert(0, click.core.Option(("-d", "--debug"), is_flag=True, help="Set log level to DEBUG"))
        self.no_args_is_help = True


def setup_logs(is_debug_level: bool) -> None:
    """
    Setup logs.
    :param is_debug_level: if True set the log level as DEBUG else INFO
    """
    log_format = dict(fmt="[%(asctime)s][%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    coloredlogs.install(
        level=logging.DEBUG if is_debug_level else logging.INFO,
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


def setup_db(db_path, overwrite_db: bool = True) -> SourcetrailDB:
    """
    Create and/or open the corresponding Sourcetrail DB.
    :param db_path: path of the db to open/create
    :param overwrite_db: if the path corresponds to an existing db, if True, it will be cleared else not
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


@click.group(context_settings=CONTEXT_SETTINGS, help="Mapper collection for firmware analysis.", no_args_is_help=True)
def pyrrha():
    pass


"""
 Filesystem mapper.
 Map ELF/PE files, their imports and their exports.
 Also map symlinks which target ELF/PE files.
"""


@pyrrha.command(
    "fs",
    cls=MapperCommand,
    short_help="Map PE and ELF files of a filesystem into a sourcetrail-compatible db.",
    help="Map a filesystem into a sourcetrail-compatible db. It maps ELF and PE files, \
their imports and their exports plus the symlinks that points on these executable files.",
)
@click.option(
    "-e",
    "--json",
    help="Create a JSON export of the resulting mapping.",
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
def fs(debug: bool, db: Path, json, jobs, resolve_duplicates, root_directory):
    setup_logs(debug)
    db_instance = setup_db(db)

    root_directory = root_directory.absolute()
    fs_mapper = FileSystemImportsMapper(root_directory, db_instance)

    fs_mapper.map(jobs, json, resolve_duplicates)

    db_instance.close()


if __name__ == "__main__":
    pyrrha()
