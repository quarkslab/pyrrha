"""Load information used by InterCGMapper from the files on the disk."""
import logging
import re
from collections import defaultdict

# third-party imports
import lief
from quokka import Program
from quokka.exc import ChunkMissingError
from quokka.types import FunctionType

# local imports
from pyrrha_mapper import Binary

QUOKKA_EXT = ".quokka"

"""
[<FunctionType.NORMAL: 1>,
 <FunctionType.IMPORTED: 2>,
 <FunctionType.LIBRARY: 3>,
 <FunctionType.THUNK: 4>,
 <FunctionType.EXTERN: 5>,
 <FunctionType.INVALID: 6>]
"""


def load_program(binary: Binary) -> None:
    """Load a binary file and its quokka file into a Binary object.

    It modifies the provided binary object in place.

    In order, it performs the following actions:
    1. load the program object
    2. use lief to extract exported symbols (handle conflicts with IDA names)
    3. checks if exported functions have been missed by IDA (but referenced in LIEF)
    4. Mangle the call graph to make external call to .PLT to directly jump on the 
       external symbol

    :param binary: binary file from which to load additional data
    :param exec_file: path to the corresponding binary file
    :return: a Program object corresponding to the given binary
    """
    # Load Quokka file to retrieve Program object
    exec_file = binary.real_path
    quokka_file = binary.auxiliary_file(append=QUOKKA_EXT)
    try:
        if quokka_file.exists():
            program = Program(quokka_file, exec_file)
        else:
            program = Program.from_binary(exec_file, quokka_file, timeout=3600)
    except ChunkMissingError as e:
        raise SyntaxError() from e
    if program is None:
        raise SyntaxError()

    # Load exports / mangling info from
    get_lief_exports_mapping(binary)

    # Load the call graph
    compute_call_graph(binary, program)


def compute_call_graph(binary: Binary, program: Program) -> None:
    """Compute the call graph of the program using Quokka/Binexport.

    It fill the call attribute of binary.

    :param binary: binary object to fill
    :param program: Program object in which to extract data
    """
    # Call graph fun_name -> [callee_name1, callee_name2]
    call_graph: dict[str, list[str]] = {}

    # Fill temporary dict
    _inter_cg = {}  # addr: (mangled_name, pp_name, addr, typ, calls: list[int])
    for f_addr, f in program.items():
        name = f.mangled_name  # as computed by IDA

        if exports.get(f_addr) or exports.get(
            f_addr + 1
        ):  # If the function is somewhat exported (and visible in LIEF)
            res = exports.get(
                f_addr, exports.get(f_addr + 1)
            )  # In THUMB mode address is address+1
            canonical_name, all_names = res
            if name != canonical_name:
                logging.info(f"change fun name: {name} -> {canonical_name}")
                name = canonical_name  # In multiple names just select the canonical one

        _inter_cg[f_addr] = (
            name,
            f.name,
            f_addr,
            f.type,
            list(set(x.start for x in f.calls)),
        )

    # Check if some exports don't have any associated function (not detected by IDA)
    for exp_addr in exports.keys() - program.keys():
        canon, allnames = exports[exp_addr]
        if p_fun := program.get(
            exp_addr - 1
        ):  # IDA keeps ARM address while LIEF use THUMB addresses
            if p_fun.mangled_name in allnames:  # Check that we have a match on names
                continue
        # else case
        logging.info(
            f"export {canon}: {hex(exp_addr)} address not found in program (add one)."
        )
        call_graph[canon] = []

    # Iterate back the temporary dict to fill the real call graph
    # The deal here is to fast-forward call to imported function directly on the 
    # imported symbol and not on the PLT (to make the graph more straightforward)
    for f_name, f_pp_name, f_addr, f_type, calls in _inter_cg.values():
        if f_type in [FunctionType.NORMAL, FunctionType.LIBRARY]:
            call_graph[f_name] = []  # add entry in call graph

            # Iter calls (ignore calls that are not pointing to a function!)
            for c_name, c_pp_name, c_addr, c_type, c_calls in [
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
                                call_graph[f_name].append(
                                    c_name
                                )  # Keep the name of the thunk "strcpy, sprintf"
                            else:  # Forward the call to the underlying function name
                                call_graph[f_name].append(sub_callee[0])
                        else:
                            call_graph[f_name].append(c_name)  # Add it normally
                    else:  # In all other cases
                        call_graph[f_name].append(c_name)  # Add it normally
                else:  # ignore function without name
                    logging.warning(
                        f"[{program.name}] {f_name} calls a function without name (at {c_addr:#08x})"
                    )

        # If thunk AND exported still keep it (for later resolution)
        elif f_type == FunctionType.THUNK and (
            (f_addr in exports) or (f_addr + 1 in exports)
        ):
            call_graph[f_name] = [_inter_cg[x][0] for x in calls if x in _inter_cg]

        else:  # THUNK, IMPORTED, EXTERN (not included in call graph)
            pass

    # Change exports dict to be: name_mangled -> name_canonical
    exports = {name: x[0] for x in exports.values() for name in x[1]}

    # Add to demangled mapping, IDA functions names from Quokka
    demangled.update({x[0]: x[1] for x in _inter_cg.values()})

    return Binary(
        -1,
        exec_file.name,
        str(exec_file),
        calls=call_graph,
        exports=exports,
        demangled=demangled,
    )


def get_lief_exports_mapping(
    binary: Binary,
) -> tuple[dict[int, tuple[str, list[str]]], dict[str, str]]:
    """
    Get the export mapping of a file as given by LIEF.

    :param binary: binary object to update
    :return: tuple of exported symbols, and demangled names dictionary
    """
    # FIXME: Try to see if there is something to do to unify with
    # FIXME: what is being done in FS-mapper
    # FIXME: it should fills both exports and demangled !
    # TODO: Maybe move to FS-mapper ?

    if not re.match(".*\.so(\.\d*)*$", str(exec_file)):
        return (
            {},
            {},
        )  # Only gather exports for .so files. Assume none are exported for other bins

    p = lief.parse(exec_file)

    # Fill dict with exported symbols
    exports = defaultdict(
        list
    )  # list there can be multiple symbols on the same address
    for s in (s for s in p.symbols if s.is_function and s.exported):
        exports[s.value].append(s.name)  # !! Add mangled name !

    # Redefine exports mapping to choose a single name for all aliases
    exports = {k: (disambiguate_export(names), names) for k, names in exports.items()}

    demangled = {
        x.name: x.demangled_name for x in p.symbols if x.is_function and x.exported
    }
    return exports, demangled


def disambiguate_export(names: list[str]) -> str:
    if len(names) == 1:
        return names[0]  # If only one no ambiguity

    chosen = None
    for name in names:
        if name.startswith("_"):
            continue
        if chosen is None:
            chosen = name
        elif chosen == name:
            continue
        else:
            # print(f"multiple options for name: {chosen}, {name}")
            if len(name) < len(chosen):
                chosen = name

    # all exports starts with _
    if chosen is None:
        logging.warning(f"cannot disambiguate: {names} (select shortest name)")
        chosen = min(names, key=len)
    return chosen
