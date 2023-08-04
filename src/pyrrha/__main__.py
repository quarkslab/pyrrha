import coloredlogs
import logging
from pathlib import Path

import click

from .db import DBInterface
from .filesystem import FileSystemMapper

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option('-d', '--debug', is_flag=True, help='set log level to DEBUG')
def pyrrha(debug):
    # define log style and level
    log_format = dict(fmt='[%(asctime)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    coloredlogs.install(level=logging.DEBUG if debug else logging.INFO,
                        level_styles={'debug'   : {'color': 'magenta'}, 'info': {'color': 'cyan'},
                                      'warning' : {'color': 'yellow'}, 'error': {'color': 'red'},
                                      'critical': {'bold': True, 'color': 'red'}},
                        field_styles={'asctime': {'color': 'green'}, 'levelname': {'bold': True}}, **log_format)


"""
 Filesystem mapper.
 Map ELF files, their imports and their exports.
 Also map symlinks which target ELF files.
"""
@pyrrha.command('fs',
                help='Map a filesystem into a sourcetrail-compatible db.')
@click.option('--db',
              help='Sourcetrail DB file path (.srctrldb).',
              type=click.Path(file_okay=True, dir_okay=True, path_type=Path),
              default=Path() / 'pyrrha.srctrldb',
              show_default=True)
@click.argument('root_directory',
                # help='Path of the directory containing the filesystem to map.',
                type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path))
def fs(db, root_directory):
    db_interface = DBInterface(db)
    root_directory = root_directory.absolute()

    mapper = FileSystemMapper(root_directory, db_interface)
    mapper.map()

    db_interface.close()


if __name__ == '__main__':
    pyrrha()
