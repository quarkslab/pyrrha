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

from enum import Enum, StrEnum, auto


class Backend(Enum):
    """Represent the backend used for Pyrrha."""

    IDA = auto()  # doc: IDA Pro disassembler
    GHIDRA = auto()  # doc: GHIDRA disassembler
    BINARY_NINJA = auto()  # doc: Binary Ninja disassembler
    QUOKKA_IDA = auto()  # doc: Use Quokka as exporter of IDA
    QUOKKA_GHIDRA = auto()  # doc: Use Quokka as exporter of Ghidra


class ResolveDuplicateOption(Enum):
    """Represent the strategy of resolution when the mapper cannot solve it."""

    IGNORE = 1  # doc: The mapper will let the conflict as unresolved.
    ARBITRARY = 2  # doc: The mapper will choose a default one.
    INTERACTIVE = 3  # doc: The user can interactively solve the conflict.


class FuncType(StrEnum):
    """Represent the type of a function."""

    IMPORTED = "imported"
    LIBRARY = "library"
    NORMAL = "normal"
    THUNK = "thunk"
