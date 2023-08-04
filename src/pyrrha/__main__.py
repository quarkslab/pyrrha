from pathlib import Path

import click

from .db import DBInterface
from .filesystem import FileSystemMapper


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def pyrrha():
    pass


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
