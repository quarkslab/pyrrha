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
"""Load information used by InterCGMapper from the files on the disk."""

import logging
from typing import NamedTuple

# third-party imports
from quokka import Program
from quokka.exc import ChunkMissingError
from quokka.types import FunctionType

# local imports
from pyrrha_mapper.common import Binary, Symbol
from pyrrha_mapper.exceptions import FsMapperError

QUOKKA_EXT = ".quokka"

logger = logging.getLogger("quokka")
logger.setLevel(logging.WARNING)

"""
[<FunctionType.NORMAL: 1>,
 <FunctionType.IMPORTED: 2>,
 <FunctionType.LIBRARY: 3>,
 <FunctionType.THUNK: 4>,
 <FunctionType.EXTERN: 5>,
 <FunctionType.INVALID: 6>]
"""


def load_program(binary: Binary, log_prefix: str = "") -> dict[Symbol, list[str]]:
    """Create a Binary object from a given file using lief and quokka.

    It modifies the provided binary object in place.

    In order, it performs the following actions:
    1. load the program object
    2. use lief to extract exported symbols (handle conflicts with IDA names)
    3. checks if exported functions have been missed by IDA (but referenced in LIEF)
    4. Mangle the call graph to make external call to .PLT to directly jump on the
        external symbol

    raise: FsMapperError if cannot load it

    :param binary: a Binary object that will be completed

    :return: a dict of called done by each symbol of the binary
    """
    file_path = binary.real_path
    if file_path is None:
        raise FileNotFoundError(file_path)

    quokka_file = binary.auxiliary_file(append=QUOKKA_EXT)
    try:
        if quokka_file.exists():
            program: Program | None = Program(quokka_file, file_path)
        else:
            program = Program.from_binary(file_path, quokka_file, timeout=3600)
    except ChunkMissingError as e:
        raise FsMapperError(e) from e
    if program is None:
        raise FsMapperError("Quokka does not produce a Program object")

    # Load the call graph
    return compute_call_graph(binary, program, log_prefix)


class _FuncData(NamedTuple):
    symbol: Symbol
    type: FunctionType
    calls: list[int]
    callers: list[int]

    @property
    def name(self) -> str:
        return self.symbol.name

    @property
    def demangled_name(self) -> str:
        return self.symbol.demangled_name

    @property
    def addr(self) -> int:
        assert self.symbol.addr
        return self.symbol.addr


def _generate_calls_list(
    func: _FuncData, call_graph: dict[int, _FuncData], log_prefix: str
) -> list[str]:
    """Given a function return its call list.

    It only contains functions that are contained in the call graph and have a name.
    """
    res = list()
    for c in [call_graph[x] for x in func.calls if x in call_graph]:
        if c.name:  # Has a true name
            res.append(c.name)  # Add it normally
        else:  # ignore function without name
            logging.warning(
                f"{log_prefix}: {func.symbol} calls a function without name (at {c.addr:#08x})"
            )
    return res


def combine_program_analysis_binary(
    binary: Binary, program: Program, log_prefix: str
) -> dict[int, _FuncData]:
    """Combine program and binary objects by computing useful data.

    It updates binary object if new functions are determined.

    :param binary: binary object to update, contain data already analyzed
    :param program: Program object in which to extract data
    :return: a dict [addr, FuncData object associated to this address]
    """
    exports = binary.exported_funcs_by_addr
    program_data: dict[int, _FuncData] = {}
    for f_addr, f in program.items():
        if f_addr in exports or f_addr + 1 in exports:  # function exported (and visible in LIEF)
            all_symbs = exports.get(
                f_addr, exports.get(f_addr + 1, [])
            )  # In THUMB mode address is address+1
            f_symb = disambiguate_export(all_symbs, log_prefix)
            if f.name != f_symb.demangled_name:
                logging.debug(f"{log_prefix}: change fun name {f.name} -> {f_symb.demangled_name}")
            if len(all_symbs) > 1:  # all the symbols will point on the chosen one
                map(lambda x: binary.replace_function(f_symb, x, True), all_symbs)
        else:
            f_symb = Symbol(name=f.mangled_name, demangled_name=f.name, is_func=True, addr=f_addr)
            binary.add_function(f_symb)

        program_data[f_addr] = _FuncData(
            symbol=f_symb,
            type=f.type,
            calls=list(set(x.start for x in f.calls)),
            callers=list(set(x.start for x in f.callers)),
        )
    return program_data


def compute_call_graph(
    binary: Binary, program: Program, log_prefix: str = ""
) -> dict[Symbol, list[str]]:
    """Compute the call graph of the program using Quokka/Binexport.

    It fill the call attribute of binary.

    :param binary: binary object to update, contain data already analyzed
    :param program: Program object in which to extract data
    """

    def _nb_initial_underscore(x: str) -> int:
        return len(x) - len(x.strip("_"))

    # Call graph fun_name -> [callee_name1, callee_name2]
    call_graph: dict[Symbol, list[str]] = {}
    exports = binary.exported_funcs_by_addr

    # Combine program and binary objects by computing useful data
    program_data = combine_program_analysis_binary(binary, program, log_prefix)

    # Check if some exports don't have any associated function (not detected by IDA)
    for exp_addr in exports.keys() - program.keys():
        all_symbs = exports[exp_addr]
        canon = disambiguate_export(all_symbs, log_prefix)
        if p_fun := program.get(exp_addr - 1):
            # IDA keeps ARM address while LIEF use THUMB addresses
            if p_fun.mangled_name in [s.name for s in all_symbs]:
                # Check that we have a match on names
                continue
        # else case
        logging.debug(
            f"{log_prefix}: export {canon.name}: {hex(exp_addr)} address not found in program(add)."
        )
        call_graph[canon] = []
        if len(all_symbs) > 1:  # all the symbols will point on the chosen one
            map(lambda x: binary.replace_function(canon, x, True), all_symbs)

    # Iterate back the temporary dict to fill the real call graph
    # The deal here is to fast-forward call to imported function directly on the
    # imported symbol and not on the PLT (to make the graph more straightforward)
    removed_trampoline: dict[str, str] = dict()
    for f in program_data.values():
        if (
            f.type in [FunctionType.NORMAL, FunctionType.LIBRARY]
            # If thunk AND exported or thunk AND call several func, keep it (for later resolution)
            or (
                f.type == FunctionType.THUNK
                and ((f.addr in exports) or (f.addr + 1 in exports) or len(f.calls) > 1)
            )
        ):
            call_graph[f.symbol] = _generate_calls_list(f, program_data, log_prefix)
            continue

        # Replace thunk calling only one function (and only one)        
        elif f.type == FunctionType.THUNK and len(f.calls) == 1 and f.calls[0] in program_data:
            sub_callee = program_data[f.calls[0]]
            if sub_callee.type in [FunctionType.IMPORTED, FunctionType.EXTERN]:
                # Keep the name of the thunk "strcpy, sprintf"
                name, target = sub_callee.name, f.name
                # in case of nested functions (starting with _, keep the less nested one)
                if _nb_initial_underscore(target) > _nb_initial_underscore(name):
                    name, target = target, name
            else:  # Forward the call to the underlying function name
                name, target = f.name, sub_callee[0].name
            # resolve trampoline and update associated dict
            while target in removed_trampoline:
                target = removed_trampoline[target]
            removed_trampoline[name] = target
            for key, val in removed_trampoline.items():
                if val == name:
                    removed_trampoline[key] = target

        # If terminal thunk keep it in binary
        elif f.type == FunctionType.THUNK and len(f.calls) == 0 and len(f.callers) > 0:  
            continue

        # remove any function not explicitely kept (THUNK, IMPORTED, EXTERN)
        if binary.get_function_by_name(f.name).addr == f.addr:
            binary.remove_function(f.name)

    return {
        symb: [removed_trampoline[c] if c in removed_trampoline else c for c in calls]
        for symb, calls in call_graph.items()
    }


def disambiguate_export(symbs: list[Symbol], log_prefix: str = "") -> Symbol:
    """Given a list of symbols associated with one address, chose one."""
    if len(symbs) == 1:
        return symbs[0]  # If only one no ambiguity

    chosen = None
    for symb in symbs:
        if symb.demangled_name.startswith("_"):
            continue
        if chosen is None:
            chosen = symb
        elif chosen == symb:
            continue
        else:
            # print(f"multiple options for name: {chosen}, {name}")
            if len(symb.demangled_name) < len(chosen.demangled_name):
                chosen = symb

    # all exports starts with _
    if chosen is None:
        options = [s.demangled_name for s in symbs]
        logging.debug(f"{log_prefix}: cannot disambiguate, select shortest name: {options}")
        chosen = min(symbs, key=lambda x: len(x.demangled_name))
    return chosen
