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
"""Utils functions related to binary exports manipulation."""

import logging
from pathlib import Path

# third-party imports
from quokka import Program
from quokka.exc import ChunkMissingError

# local imports
from pyrrha_mapper.exceptions import FsMapperError

QUOKKA_EXT = ".quokka"

logger = logging.getLogger("quokka")
logger.setLevel(logging.WARNING)


def load_program_export(bin_path: Path, log_prefix: str = "") -> Program:
    """:return: the binary export of the given binary"""
    if bin_path is None:
        raise FileNotFoundError(bin_path)

    quokka_file = bin_path.with_suffix(bin_path.suffix + QUOKKA_EXT)
    try:
        if quokka_file.exists():
            logging.info(f"{log_prefix}: loading existing Quokka file")
            program: Program | None = Program(quokka_file, bin_path)
        else:
            logging.info(f"{log_prefix}: compute Quokka file")
            program = Program.from_binary(bin_path, quokka_file, timeout=3600)
    except ChunkMissingError as e:
        raise FsMapperError() from e
    if program is None:
        raise FsMapperError("No program object generated.")
    return program
