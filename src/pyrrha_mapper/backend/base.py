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
"""Interface for backends used by mappers."""

from abc import ABCMeta, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from pyrrha_mapper.types import FuncType


class Backend(object, metaclass=ABCMeta):
    """Abstraction of any backend used to run analysis."""

    def __init__(
        self,
        bin_path: Path, 
        root_directory: Path | None,
        decompilation: bool = False,
        image_base: int = 0,
    ) -> None:
        """Open the binary parser and run any required analysis."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the binary parser and release all resources."""
        ...

    @abstractmethod
    def is_func_start(self, addr: int) -> bool:
        """:return: True if *addr* (parser space) is the entry point of a function."""
        ...

    @property
    @abstractmethod
    def func_addrs(self) -> Iterator[int]:
        """Yield the parser-space entry-point address of every known function."""

    @abstractmethod
    def func_mangled_name(self, addr: int) -> str:
        """:return:: the raw name of a function at *addr*."""
        ...

    @abstractmethod
    def func_demangled_name(self, addr: int) -> str:
        """:return: the demangled name, falling back to the mangled name."""
        ...

    @abstractmethod
    def func_children(self, addr: int) -> list[int]:
        """:return: entry-point addresses of callees of the function at *addr*."""
        ...

    @abstractmethod
    def func_parents(self, addr: int) -> list[int]:
        """:return: entry-point addresses of callers of the function at *addr*."""
        ...

    @abstractmethod
    def func_type(self, addr: int) -> FuncType:
        """:return: the FuncType of the function at *addr*.

        Thunk stubs that resolve to external/imported functions must return
        ``FuncType.IMPORTED`` so the trampoline resolution in ``__init__``
        correctly forwards callers to the imported symbol name.
        """
        ...

    @abstractmethod
    def func_decompiled(self, addr: int) -> str:
        """:return: decompilation result of the function"""
        ...
