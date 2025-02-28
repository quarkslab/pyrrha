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
"""Types shared in multiple mappers."""

from enum import Enum, auto


class Disassembler(Enum):
    """Represent a SRE (Software Reverse Engineering tool, a disassembler)."""

    AUTO = auto()  # doc: Disassembler shall selected automatically
    IDA = auto()  # doc: IDA Pro disassembler
    GHIDRA = auto()  # doc: GHIDRA disassembler
    BINARY_NINJA = auto()  # doc: Binary Ninja disassembler


class Exporters(Enum):
    """Represent export file formats used in some of the mappers."""

    AUTO = auto()  # doc: The exporter shall be automatically selected
    BINEXPORT = auto()  # doc: Use Binexport as exporter
    QUOKKA = auto()  # doc: Use Quokka as exporter


class ResolveDuplicateOption(Enum):
    """Represent the strategy of resolution when the mapper cannot solve it."""

    IGNORE = 1  # doc: The mapper will let the conflict as unresolved.
    ARBITRARY = 2  # doc: The mapper will choose a default one.
    INTERACTIVE = 3  # doc: The user can interactively solve the conflict.
