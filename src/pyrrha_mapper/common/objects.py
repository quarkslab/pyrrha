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
"""Objects which represent filesystem components (binaries, symlinks, filesystem)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from enum import Enum, auto
from functools import reduce
from pathlib import Path
from typing import Any, Self

from pydantic import (
    BaseModel,
    Field,
    PrivateAttr,
    SerializationInfo,
    ValidationInfo,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)


class Symbol(BaseModel):
    """Class to represent a Symbol of a binary."""

    name: str
    demangled_name: str
    is_func: bool = False
    id: int | None = None
    addr: int | None = Field(frozen=True, default=None)

    # from https://github.com/pydantic/pydantic/discussions/2910
    def __lt__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) < tuple(other.model_dump().values())

    def __le__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) <= tuple(other.model_dump().values())

    def __gt__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) > tuple(other.model_dump().values())

    def __ge__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) >= tuple(other.model_dump().values())

    def __repr__(self):  # noqa: D105
        return f"Symbol('{self.name}')"

    def __hash__(self) -> int:  # noqa: D105
        return hash(tuple(self.model_dump().values()))


class FileSystemComponent(BaseModel):
    """Base class representing any filesystem object (including its optionnal DB id)."""

    path: Path
    id: int | None = None
    name: str = ""
    real_path: Path | None = None  # Path on host filesystem computed at load time

    def model_post_init(self, __context: Any) -> None:
        """Enforce object name based on its path."""
        self.name = self.path.name

    # from https://github.com/pydantic/pydantic/discussions/2910
    def __lt__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) < tuple(other.model_dump().values())

    def __le__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) <= tuple(other.model_dump().values())

    def __gt__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) > tuple(other.model_dump().values())

    def __ge__(self, other):  # noqa: D105
        return tuple(self.model_dump().values()) >= tuple(other.model_dump().values())


class Binary(FileSystemComponent):
    """Class that represents a binary. It stores symbols/lib imported and exported."""

    imported_libraries: dict[str, Binary | None] = Field(default_factory=dict)
    imported_symbols: dict[str, Symbol | None] = Field(default_factory=dict)
    exported_symbols: dict[str, Symbol] = Field(
        default_factory=dict
    )  # warning only symbols which are not functions
    exported_functions: dict[str, Symbol] = Field(default_factory=dict)

    # Fields for call graph representation
    # functions is both: internal functions + exported functions
    internal_functions: dict[str, Symbol] = Field(default_factory=dict)
    calls: dict[str, list[Symbol]] = Field(default_factory=dict)

    # ELF specific fields
    version_requirement: dict[str, list[str]] = Field(
        default_factory=dict
    )  # dict(symbol_name, list(requirements))

    @field_validator("internal_functions", "exported_functions", mode="after")
    @classmethod
    def validate_functions_field(cls, value: dict[str, Symbol]) -> dict[str, Symbol]:
        """Ensure that each member of the functions field is a function."""
        for symb in value.values():
            if not symb.is_func:
                raise ValueError(
                    f"symbol '{symb}' cannot be a function as 'is_func' is set to False"
                )
        return value

    def add_call(self, caller: Symbol | str, callee: Symbol) -> None:
        """Add a call to the callee from the caller function.

        Caller should be in the current binary.
        """
        if isinstance(caller, Symbol):
            caller = caller.name
        assert self.function_exists(caller), f"Function {caller} does not exists in {self.name}"
        if caller not in self.calls:
            self.calls[caller] = [callee]
        elif callee not in self.calls[caller]:
            self.calls[caller].append(callee)

    def add_imported_library_name(self, name: str) -> None:
        """Add an imported library name."""
        self.imported_libraries[name] = None

    def add_imported_symbol_name(self, name: str) -> None:
        """Add an imported symbol name."""
        self.imported_symbols[name] = None

    def add_imported_library(self, lib: Binary) -> None:
        """Store an imported library with its corresponding Binary object."""
        self.imported_libraries[lib.name] = lib

    def add_imported_symbol(self, symbol: Symbol) -> None:
        """Add an imported Symbol object."""
        self.imported_symbols[symbol.name] = symbol

    def add_non_resolved_imported_library(self, lib_name: str) -> None:
        """Add a library which is not resolved."""
        self.imported_libraries[lib_name] = None

    def add_non_resolved_imported_symbol(self, symbol_name: str) -> None:
        """Add a symbol which is not resolved."""
        self.imported_symbols[symbol_name] = None

    def add_exported_symbol(self, symbol: Symbol, symbol_name: str = "") -> None:
        """Record a Symbol in the current binary and flag it as exported.

        If the symbol is a function, record it also in the binary's functions.
        It overrides old symbol with the same name.
        It is possible to record a symbol under another name by specifying symbol_name
        parameter.
        """
        if not symbol_name:
            symbol_name = symbol.name
        if symbol.is_func:
            self.exported_functions[symbol_name] = symbol
            self.exported_symbols.pop(symbol_name, None)
        else:
            self.exported_symbols[symbol_name] = symbol
            self.exported_functions.pop(symbol_name, None)

    def add_function(self, func: Symbol, func_name: str = "") -> None:
        """Record a Function in the current binary.

        It overrides old function with the same name.
        It is possible to record a function under another name by specifying its name in
        parameter.
        """
        assert func.is_func
        if not func_name:
            func_name = func.name
        self.internal_functions[func_name] = func

    def remove_function(self, func_name) -> None:
        """Remove a Function in the current binary."""
        res = self.exported_functions.pop(func_name, self.internal_functions.pop(func_name, None))
        if res is None:
            raise KeyError(func_name)
        if func_name in self.calls:
            self.calls.pop(func_name)

    def remove_imported_symbol(self, name) -> None:
        """Remove an imported symbol in the current binary."""
        self.imported_symbols.pop(name)

    def exported_symbol_exists(self, symbol_name: str) -> bool:
        """:return: true if an exported symbol exists in the current Binary."""
        return symbol_name in self.exported_symbols or symbol_name in self.exported_functions

    def exported_function_exists(self, symbol_name: str) -> bool:
        """:return: true if an exported function exists in the current Binary."""
        return symbol_name in self.exported_functions

    def imported_symbol_exists(self, symb_name: str, is_resolved: bool = True) -> bool:
        """:return: true if an imported symbol exists in the current Binary

        you can optionnaly select if the lib should be resolved or not
        """
        return symb_name in self.imported_symbols and (
            (not is_resolved) or self.imported_symbols[symb_name] is not None
        )

    def imported_library_exists(self, lib_name: str, is_resolved: bool = True) -> bool:
        """:return: true if an imported lib exists in the current Binary

        you can optionnaly select if the lib should be resolved or not
        """
        return lib_name in self.imported_libraries and (
            (not is_resolved) or self.imported_libraries[lib_name] is not None
        )

    def function_exists(self, symbol_name: str) -> bool:
        """:return: true if an function exists in the current Binary."""
        return symbol_name in self.exported_functions or symbol_name in self.internal_functions

    def get_calls_from(self, caller: Symbol | str) -> list[Symbol]:
        """:return: list of functions called by the given function"""
        if isinstance(caller, Symbol):
            caller = caller.name
        if caller in self.calls:
            return self.calls[caller]
        return []

    def get_exported_symbol(self, symbol_name: str) -> Symbol:
        """:return: the exported symbol with the given name."""
        res = self.exported_functions.get(symbol_name, self.exported_symbols.get(symbol_name))
        if res is None:
            raise KeyError(symbol_name)
        return res

    def get_imported_symbol(self, symbol_name: str) -> Symbol:
        """:return: the imported symbol with the given name."""
        res = self.imported_symbols[symbol_name]
        if res is None:
            raise KeyError(symbol_name)
        return res

    def get_function_by_name(self, func_name: str) -> Symbol:
        """:return: the function with the given name."""
        res = self.exported_functions.get(func_name, self.internal_functions.get(func_name))
        if res is None:
            raise KeyError(func_name)
        return res

    def iter_exported_symbols(self) -> Iterable[Symbol]:
        """:return: an iterable over the exported symbols stored in the Binary."""
        yield from self.exported_symbols.values()
        yield from self.exported_functions.values()

    def iter_exported_functions(self) -> Iterable[Symbol]:
        """:return: an iterable over the exported functions stored in the Binary."""
        yield from self.exported_functions.values()

    def iter_exported_function_names(self) -> Iterable[str]:
        """:return: an iterable over the exported function names stored in the Binary.

        It can useful to use this function if functions are stored under a name
        different from their symbol
        """
        yield from self.exported_functions.keys()

    def iter_not_exported_functions(self) -> Iterable[Symbol]:
        """:return: an iterable over the exported functions stored in the Binary."""
        yield from self.internal_functions.values()

    def iter_imported_libraries(self) -> Iterable[Binary]:
        """:return: an iterable over the imported libraries stored in the Binary."""
        for lib in self.imported_libraries.values():
            if lib is not None:
                yield lib

    def iter_imported_symbols(self) -> Iterable[Symbol]:
        """:return: an iterable over the imported symbols stored in the Binary."""
        for symbol in self.imported_symbols.values():
            if symbol is not None:
                yield symbol

    def iter_functions(self) -> Iterable[Symbol]:
        """:return: an iterable over the functions in the Binary."""
        yield from self.internal_functions.values()
        yield from self.exported_functions.values()

    @property
    def imported_library_names(self) -> list[str]:
        """:return: the list of the imported library names."""
        return list(self.imported_libraries.keys())

    @property
    def imported_symbol_names(self) -> list[str]:
        """:return: the list of the imported symbols names."""
        return list(self.imported_symbols.keys())

    @property
    def exported_funcs_by_addr(self) -> dict[int, list[Symbol]]:
        """:return: a dict [addr, list of exported symbols at this addr] for a given binary"""
        exports: dict[int, list[Symbol]] = dict()
        for s in self.iter_exported_functions():
            if s.addr is None:
                continue
            elif s.addr not in exports:
                exports[s.addr] = [s]
            else:
                exports[s.addr].append(s)
        return exports

    def replace_function(self, new_func: Symbol, old_func: Symbol, keep_old_name: bool) -> None:
        """Replace a function by a new one.

        If keep_old_name, will be registered with the same name as the previous one.
        """
        assert new_func.is_func and old_func.is_func
        if new_func == old_func:
            return
        if keep_old_name:
            name = old_func.name
        else:
            name = new_func.name
        if self.exported_function_exists(old_func.name):
            self.add_exported_symbol(new_func, symbol_name=name)
        else:
            self.add_function(new_func, func_name=name)

    def __repr__(self):  # noqa: D105
        return f"Binary('{self.path}')"

    def auxiliary_file(self, extension="", append="") -> Path:
        """Compute path of an auxiliary file next to the current one.

        Get the Path object of an auxiliary file located in the
        same directory directory than the current binary. This
        utility function enables accessing quickly files stored
        along a binary.

        :param extension: file extension that shall be returned (replace current one)
        :param append: suffix that will be added to the current file name
        :return: new Path object (as on the host)
        """
        if self.real_path is None:
            raise AttributeError("real path should be set to compute auxiliary file")
        if extension and append:
            raise NameError("cannot combine extention and append")
        if extension:
            return self.real_path.with_suffix(extension)
        elif append:
            return Path(str(self.real_path) + append)
        else:
            raise NameError("auxiliary file requires either extension or append argument")


class TargetType(Enum):
    """Enum used for serialization."""

    BINARY = auto()
    SYMLINK = auto()


class Symlink(FileSystemComponent):
    """Class that represents a Symlink and store the associated DB id."""

    target: Binary | Symlink

    @computed_field  # type: ignore[misc]
    @property
    def target_type(self) -> TargetType:
        """:return: type of the target"""
        if isinstance(self.target, Binary):
            return TargetType.BINARY
        elif isinstance(self.target, Symlink):
            return TargetType.SYMLINK
        else:
            raise ValueError("Target is not a Binary object neither a Symlink one.")

    @computed_field  # type: ignore[misc]
    @property
    def target_path(self) -> Path:
        """:return: path of the target"""
        return self.target.path

    def __repr__(self):  # noqa: D105
        return f"Symlink({self.path} -> {self.target.path})"


class FileSystem(BaseModel):
    """Class (to store and manipulate all the data relative to a filesystem.

    For the moment it only stores Binary and Symlinks objects.
    It is based on pydantic so it can be dump into a dict/json and be created from these
    dumps.
    """

    root_dir: Path
    binaries: dict[Path, Binary] = Field(default_factory=dict)
    symlinks: dict[Path, Symlink] = Field(default_factory=dict)
    _binary_names: dict[str, list[Binary]] = PrivateAttr(default_factory=dict, init=False)
    _symlink_names: dict[str, list[Symlink]] = PrivateAttr(default_factory=dict, init=False)

    def __repr__(self):  # noqa: D105
        return (
            f"FileSystem(root='{self.root_dir}',"
            f"bins={len(self.binaries)}, symlinks={len(self.symlinks)})"
        )

    # ------------------------------ Overload Pydantic methods -------------------------
    # Always export by aliases, set always excluded attributes
    @field_serializer(
        "binaries", mode="plain", when_used="always", return_type=dict[str | Path, dict]
    )
    def fs_bin_serializer(self, v: dict[Path, Binary], info: SerializationInfo) -> Any:
        """Serialize the current FS instance into a json dump or a dict dump."""
        res = dict()
        mode = "json" if info.mode_is_json() else "python"

        for path, binary in v.items():
            if info.mode_is_json():
                path = str(path)  # type: ignore[assignment]
            if binary is None:
                raise ValueError(f"{path} has no data associated")
            res[path] = binary.model_dump(
                mode=mode,
                include={
                    "id": True,
                    "path": True,
                    "name": True,
                    "imported_symbols": True,
                    "exported_symbols": True,
                    "exported_functions": True,
                    "internal_functions": True,
                    "calls": True,
                },
            )
            res[path]["imported_libraries"] = dict()
            for n, _bin in binary.imported_libraries.items():
                if _bin is None:
                    res[path]["imported_libraries"][n] = None
                else:
                    res[path]["imported_libraries"][n] = _bin.model_dump(
                        mode=mode, include={"path": True}
                    )
        return res

    @field_serializer(
        "symlinks", mode="plain", when_used="always", return_type=dict[str | Path, dict]
    )
    def fs_sym_serializer(self, v: dict[Path, Binary], info: SerializationInfo) -> Any:
        """Serialize the current FS instance into a json dump or a dict dump."""
        res = dict()
        mode = "json" if info.mode_is_json() else "python"

        for path, sym in v.items():
            if info.mode_is_json():
                path = str(path)  # type: ignore[assignment]
            if sym is None:
                raise ValueError(f"{path} has no data associated")
            res[path] = sym.model_dump(mode=mode, exclude={"target": True})
        return res

    @field_validator("binaries", mode="plain")
    @classmethod
    def fs_bin_validate(cls, data: Any, info: ValidationInfo) -> Any:
        """Validate a dict dump and transform it into a correct `binaries` field."""
        if not isinstance(data, dict):
            raise ValueError("provided data is not a dict")
        if info.field_name == "binaries" and reduce(
            lambda x, y: x and isinstance(y[0], Path) and isinstance(y[1], Binary),
            data.items(),
            True,  # correct equivalent to `isinstance(data, dict[Path, Binary])`
        ):
            return data

        # generate first version of res
        res: dict[Path, Binary] = dict()
        imported_libs: dict[Path, dict[str, dict[str, Any]]] = dict()
        # first part: automatic conversion
        for path, content in data.items():
            try:
                path = Path(path)
            except TypeError as e:
                raise ValueError(f"Cannot convert '{path}' into a pathlib.Path object: {e}") from e
            if not isinstance(content, dict):
                raise ValueError(f"There is no content associated to {path} in the provided data")
            # save imported libs separetely as it should be treated manually
            imported_libs[path] = (
                content.pop("imported_libraries") if "imported_libraries" in content else dict()
            )
            # convert the content into a Binary object
            bin_obj = Binary.model_validate(content)
            if bin_obj.path != path:
                raise ValueError("path mismatches between binary object and its export")
            res[path] = bin_obj
        # second part: manually generate imported_libs field of each Binary object
        for bin_path, libs in imported_libs.items():
            for name, lib_path in libs.items():
                if lib_path is None:
                    res[bin_path].add_imported_library_name(name)
                else:
                    try:
                        lib_path_obj = Path(lib_path["path"])
                    except TypeError as e:
                        raise ValueError(
                            f"Cannot convert '{lib_path['path']}' into Path object: {e}"
                        ) from e
                    if lib_path_obj not in res:
                        raise ValueError(f"Imported lib '{lib_path}' not listed in binaries")
                    res[bin_path].add_imported_library(res[lib_path_obj])

        # optmimize version by replacing every iteration of the same symbol (same id)
        # by one object
        # 1. generate dict of symbols by ids
        symbols_by_ids: dict[int, Symbol] = {
            s.id: s for bin in res.values() for s in bin.iter_exported_symbols() if s.id is not None
        }
        # 2. Replace same symbols objects by one object
        for bin in res.values():
            for symb in list(bin.iter_imported_symbols()):
                if symb.id is not None and symb.id in symbols_by_ids:
                    bin.add_imported_symbol(symbols_by_ids[symb.id])

        return res

    @field_validator("symlinks", mode="plain")
    @classmethod
    def fs_sym_validate(cls, data: Any, info: ValidationInfo) -> Any:
        """Validate a dict dump and transform it into a correct `symlinks` field."""
        if not isinstance(data, dict):
            raise ValueError("provided data is not a dict")
        if info.field_name == "symlinks" and reduce(
            lambda x, y: x and isinstance(y[0], Path) and isinstance(y[1], Symlink),
            data.items(),
            True,  # correct equivalent to `isinstance(data, dict[Path, Symlink])`
        ):
            return data

        # generate first version of res
        res: dict[Path, Symlink] = dict()
        untreated_symlinks: dict[Path, dict] = dict()
        # first part: automatic conversion
        for path, content in data.items():
            try:
                validated_path = Path(path)
            except TypeError as e:
                raise ValueError(f"Cannot convert '{path}' into a pathlib.Path object: {e}") from e
            if isinstance(content, Symlink):
                res[validated_path] = data[path]
                continue
            if not isinstance(content, dict):
                raise ValueError(f"There is no content associated to {path} in the provided data")
            if "target_path" not in content or "target_type" not in content:
                res[validated_path] = cls.__symlink_convert(content, validated_path)
                continue

            target_type = TargetType(content.pop("target_type"))
            try:
                content["target_path"] = Path(content["target_path"])
                target_path = content["target_path"]
            except TypeError as e:
                raise ValueError(
                    f"Cannot convert '{content['target_path']}' into a pathlib.Path object: {e}"
                ) from e
            if target_type is TargetType.BINARY:
                try:
                    content["target"] = info.data["binaries"][target_path]
                except KeyError as e:
                    raise ValueError(
                        f"Targeted object {target_path} does not exist in this FS"
                    ) from e
                res[validated_path] = cls.__symlink_convert(content, validated_path)
            else:
                content["target_path"] = target_path
                untreated_symlinks[validated_path] = content

        # check if any untreated symlink points on a non existing path
        for content in untreated_symlinks.values():
            target_path = content["target_path"]
            if target_path not in untreated_symlinks and target_path not in res:
                raise ValueError(f"Targeted object {target_path} does not exist in this FS")

        # then recursively resolve symlinks
        nb_symlinks = len(res) + len(untreated_symlinks)
        while len(res) < nb_symlinks:
            for path, content in untreated_symlinks.items():
                target_path = content["target_path"]
                if target_path in res:
                    content["target"] = res[target_path]
                    res[path] = cls.__symlink_convert(content, path)
                    untreated_symlinks.pop(path)

        return res

    @staticmethod
    def __symlink_convert(content: dict, correct_path: Path) -> Symlink:
        sym_obj = Symlink.model_validate(content)
        if sym_obj.path != correct_path:
            raise ValueError("path mismatches between sym object and its export")
        return sym_obj

    @model_validator(mode="after")
    def finalize_sym_validation(self) -> Self:
        """Finalize validation of symlinks target by accessing full fs."""
        for sym in self.iter_symlinks():
            try:
                if sym.target_type is TargetType.BINARY:
                    sym.target = self.get_binary_by_path(sym.target_path)
                elif sym.target_type is TargetType.SYMLINK:
                    sym.target = self.get_symlink_by_path(sym.target_path)
                else:
                    raise ValueError("Target type is not a value of the correct enum.")
            except KeyError as e:
                raise ValueError(
                    f"Targeted object {sym.target_path} does not exist in this FS"
                ) from e
        return self

    def model_post_init(self, __context: Any) -> None:
        """Automatically called after class instanciation, compute internal dicts."""
        for binary in self.binaries.values():
            self._set_object_realpath(binary)
            self._record_component_name(binary)
        for link in self.symlinks.values():
            self._set_object_realpath(link)
            self._record_component_name(link)

    def model_dump_json(self, **args) -> str:
        """Override classic pydantic model_dump_json with preselected arguments."""
        return json.dumps(self.model_dump(mode="json", **args))

    def write(self, export_path: Path) -> None:
        """Dump content of the instance into a JSON file."""
        export_path.write_text(self.model_dump_json())

    @classmethod
    def from_json_export(cls, export_path: Path | str):
        """Create an populate an FS instance from a json file content."""
        export_path = Path(export_path)
        return cls.model_validate_json(export_path.read_text())

    # -------------------------- Firmware manipulation helpers -------------------------
    def gen_fw_path(self, path: Path) -> Path:
        """Generate the path of a given file inside the firmware.

        :param path: path of the file on the local system
        :return: path of the file inside the firmware
        """
        return Path(self.root_dir.anchor).joinpath(path.relative_to(self.root_dir))

    def _record_component_name(self, fs_object: Binary | Symlink) -> None:
        if isinstance(fs_object, Binary):
            names_dict: dict[str, list[Binary]] = self._binary_names  # type: ignore
        else:
            names_dict: dict[str, list[Symlink]] = self._symlink_names  # type: ignore
        if fs_object.name in names_dict:
            names_dict[fs_object.name].append(fs_object)  # type: ignore
        else:
            names_dict[fs_object.name] = [fs_object]  # type: ignore

    def _set_object_realpath(self, obj: FileSystemComponent) -> None:
        obj.real_path = Path(self.root_dir) / ("." + str(obj.path))

    # --------------------- Add/get/manipulate data (binary & symlinks) ----------------

    def add_binary(self, binary: Binary) -> None:
        """Record binary in the current FS object."""
        self._set_object_realpath(binary)
        self.binaries[binary.path] = binary
        self._record_component_name(binary)

    def add_symlink(self, symlink: Symlink) -> None:
        """Record symlink in the current FS object."""
        self._set_object_realpath(symlink)
        self.symlinks[symlink.path] = symlink
        self._record_component_name(symlink)

    def binary_exists(self, binary: Binary | Path) -> bool:
        """:return: true if the given binary path correspond to a recorded binary."""
        if isinstance(binary, Binary):
            binary = binary.path
        return binary in self.binaries and self.get_binary_by_path(binary) is not None

    def symlink_exists(self, symlink: Symlink | Path) -> bool:
        """return: true if the path of the symlink correspond to a recorded symlink."""
        if isinstance(symlink, Symlink):
            symlink = symlink.path
        return symlink in self.symlinks

    def binary_name_exists(self, name: str) -> bool:
        """return: true if the given name is stored in the current FS instance."""
        return name in self._binary_names

    def symlink_name_exists(self, name: str) -> bool:
        """return: true if the given name is stored in the current FS instance."""
        return name in self._symlink_names

    def get_binaries_by_name(self, name: str) -> list[Binary]:
        """:return: the binaries with the given path."""
        return self._binary_names[name]

    def get_binary_by_path(self, path: Path) -> Binary:
        """:return: the binary with the given path."""
        return self.binaries[path]

    def get_symlinks_by_name(self, name: str) -> list[Symlink]:
        """:return: the symlinks with the given path."""
        return self._symlink_names[name]

    def get_symlink_by_path(self, path: Path) -> Symlink:
        """:return: the symlink with the given path."""
        return self.symlinks[path]

    def iter_binaries(self) -> Iterable[Binary]:
        """:return: an iterable over the binaries stored in the current FS instance."""
        for binary in self.binaries.values():
            yield binary

    def iter_symlinks(self) -> Iterable[Symlink]:
        """:return: an iterable over the symlinks stored in the current FS instance."""
        for symlink in self.symlinks.values():
            yield symlink

    def resolve_symlink(self, symlink: Symlink) -> Binary | None:
        """Resolve recursively the symlink.

        :return: its final target
        """
        current_symlink = symlink
        while self.symlink_exists(current_symlink.target.path):
            current_symlink = self.get_symlink_by_path(current_symlink.target.path)
        if not self.binary_exists(current_symlink.target.path):
            return None
        return self.get_binary_by_path(current_symlink.target.path)
