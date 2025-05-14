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
"""Common objects that can be used for any mapper."""

from .filesystem_mapper import FileSystemMapper, hide_progress
from .objects import Binary, FileSystem, Symbol, Symlink

__all__ = [
    "FileSystemMapper",
    "Binary",
    "FileSystem",
    "hide_progress",
    "Symbol",
    "Symlink",
]
