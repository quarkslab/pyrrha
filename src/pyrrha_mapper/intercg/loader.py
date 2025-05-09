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

# third-party imports
from quokka import Program
from quokka.exc import ChunkMissingError
from quokka.types import FunctionType

# local imports
from pyrrha_mapper.common import Binary, Symbol
from pyrrha_mapper.exceptions import FsMapperError

QUOKKA_EXT = ".quokka"

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
    """
    file_path = binary.real_path
    if file_path is None:
        raise FsMapperError()

    quokka_file = binary.auxiliary_file(append=QUOKKA_EXT)
    try:
        if quokka_file.exists():
            program: Program | None = Program(quokka_file, file_path)
        else:
            program = Program.from_binary(file_path, quokka_file, timeout=3600)
    except ChunkMissingError as e:
        raise FsMapperError() from e
    if program is None:
        raise FsMapperError()

    # Load the call graph
    return compute_call_graph(binary, program, log_prefix)


def compute_call_graph(
    binary: Binary, program: Program, log_prefix: str = ""
) -> dict[Symbol, list[str]]:
    """Compute the call graph of the program using Quokka/Binexport.

    It fill the call attribute of binary.

    :param binary: binary object to fill
    :param program: Program object in which to extract data
    """
    # Call graph fun_name -> [callee_name1, callee_name2]
    call_graph: dict[Symbol, list[str]] = {}

    exports: dict[int, list[Symbol]] = dict()
    for s in binary.iter_exported_functions():
        if s.addr is None:
            continue
        elif s.addr not in exports:
            exports[s.addr] = [s]
        else:
            exports[s.addr].append(s)

    # Fill temporary dict
    _inter_cg: dict[
        int, tuple[Symbol, str, str, int, FunctionType, list[int]]
    ] = {}  # addr: (pyrrha symbol, mangled_name, pp_name, addr, typ, calls: list[int])
    for f_addr, f in program.items():
        name = f.mangled_name  # as computed by IDA
        if (
            f_addr in exports or f_addr + 1 in exports
        ):  # If the function is somewhat exported (and visible in LIEF)
            all_symbs = exports.get(
                f_addr, exports.get(f_addr + 1, [])
            )  # In THUMB mode address is address+1
            canonical = disambiguate_export(all_symbs, log_prefix)
            if name != canonical.name:
                logging.info(
                    f"{log_prefix}: change fun name {name} -> {canonical.name}"
                )
                name = canonical.name  # In multiple names just select the canonical one
            f_symb = canonical
        else:
            f_symb = Symbol(name=name, demangled_name=f.name, is_func=True, addr=f_addr)
            binary.add_function(f_symb)  # FIXME : c'est bien une fonction interne ???
        _inter_cg[f_addr] = (
            f_symb,
            name,
            f.name,
            f_addr,
            f.type,
            list(set(x.start for x in f.calls)),
        )

    # Check if some exports don't have any associated function (not detected by IDA)
    for exp_addr in exports.keys() - program.keys():
        all_symbs = exports[exp_addr]
        canon = disambiguate_export(all_symbs, log_prefix)
        if p_fun := program.get(
            exp_addr - 1
        ):  # IDA keeps ARM address while LIEF use THUMB addresses
            if p_fun.mangled_name in [
                s.name for s in all_symbs
            ]:  # Check that we have a match on names
                continue
        # else case
        logging.info(
            f"{log_prefix}: export {canon.name}: {hex(exp_addr)} address not found \
in program (add)."
        )
        call_graph[canon] = []

    # Iterate back the temporary dict to fill the real call graph
    # The deal here is to fast-forward call to imported function directly on the
    # imported symbol and not on the PLT (to make the graph more straightforward)
    for f_symb, f_name, _, f_addr, f_type, calls in _inter_cg.values():
        call_graph[f_symb] = []
        if f_type in [FunctionType.NORMAL, FunctionType.LIBRARY]:
            # Iter calls (ignore calls that are not pointing to a function!)
            for _, c_name, _, c_addr, c_type, c_calls in [
                _inter_cg[x] for x in calls if x in _inter_cg
            ]:
                if c_name:  # Has a true name
                    if c_type == FunctionType.THUNK and c_addr not in exports:
                        if (
                            len(c_calls) == 1
                        ):  # The callee calls something else (and only one)
                            sub_callee = (
                                _inter_cg[c_calls[0]]
                                if c_calls[0] in _inter_cg
                                else None
                            )
                            if sub_callee is None:
                                continue  # Do not do anything if not pointing to a func
                            if sub_callee[3] in [
                                FunctionType.IMPORTED,
                                FunctionType.EXTERN,
                            ]:
                                call_graph[f_symb].append(
                                    c_name
                                )  # Keep the name of the thunk "strcpy, sprintf"
                            else:  # Forward the call to the underlying function name
                                call_graph[f_symb].append(sub_callee[0].name)
                        else:
                            call_graph[f_symb].append(c_name)  # Add it normally
                    # Add it normally
                    else:  # In all other cases
                        call_graph[f_symb].append(c_name)  # Add it normally
                else:  # ignore function without name
                    logging.warning(
                        f"{log_prefix}: [{program.name}] {f_name} calls a function \
without name (at {c_addr:#08x})"
                    )

        # If thunk AND exported still keep it (for later resolution)
        elif f_type == FunctionType.THUNK and (
            (f_addr in exports) or (f_addr + 1 in exports)
        ):
            call_graph[f_symb] = [_inter_cg[x][1] for x in calls if x in _inter_cg]

        else:  # THUNK, IMPORTED, EXTERN (not included in call graph)
            pass

    return call_graph


def disambiguate_export(symbs: list[Symbol], log_prefix: str = "") -> Symbol:
    """Given a list of symbols associated with one address, chose one."""
    if len(symbs) == 1:
        return symbs[0]  # If only one no ambiguity

    chosen = None
    for symb in symbs:
        if symb.name.startswith("_"):
            continue
        if chosen is None:
            chosen = symb
        elif chosen == symb:
            continue
        else:
            # print(f"multiple options for name: {chosen}, {name}")
            if len(symb.name) < len(chosen.name):
                chosen = symb

    # all exports starts with _
    if chosen is None:
        logging.warning(
            f"{log_prefix}: cannot disambiguate: {[s.name for s in symbs]} \
(select shortest name)"
        )
        chosen = min(symbs, key=lambda x: len(x.name))
    return chosen
