from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
import re
from collections import defaultdict
import logging

import lief
from quokka import Program
from quokka.types import FunctionType
from quokka.exc import ChunkMissingError


'''
[<FunctionType.NORMAL: 1>,
 <FunctionType.IMPORTED: 2>,
 <FunctionType.LIBRARY: 3>,
 <FunctionType.THUNK: 4>,
 <FunctionType.EXTERN: 5>,
 <FunctionType.INVALID: 6>]
'''



@dataclass
class Binary:
    pyrrha_id: int
    name: str
    path: str
    calls: dict[str, list[str]]
    exports: dict[str, str]  # Mangled -> Canonical
    demangled: dict[str, str]  # Mangled -> Demangled

    def __hash__(self) -> int:
        return hash(self.path)

    @cached_property
    def export_set(self) -> set[str]:
        return set(x for l in self.exports.values() for x in l)

    def to_dict(self) -> dict:
        return {
            "pyrrha_id": self.pyrrha_id,
            "name": self.name,
            "path": self.path,
            "calls": self.calls,
            "exports": self.exports,
            "demangled": self.demangled
        }


    @staticmethod
    def load_program(quokka_file: str | Path, exec_file: str | Path) -> 'Binary':
        """
        Load a binary file and its quokka file into a Binary object.
        In order, it performs the following actions:
        1. load the program object
        2. use lief to extract exported symbols
        3.

        :param quokka_file:
        :param exec_file:
        :return:
        """
        # Load Quokka file to retrieve Program object
        quokka_file, exec_file = Path(quokka_file), Path(exec_file)
        try:
            if quokka_file.exists():
                program = Program(quokka_file, exec_file)
            else:
                program = Program.from_binary(exec_file, f"{exec_file}.quokka", timeout=3600)
        except ChunkMissingError as e:
            raise SyntaxError()
        if program is None:
            raise SyntaxError()

        # Load exports / mangling info from
        exports, demangled = Binary.get_lief_exports_mapping(program.executable.exec_file)


        # Call graph fun_name -> [callee_name1, callee_name2]
        call_graph: dict[str, list[str]] = {}

        # Fill temporary dict
        _inter_cg = {}  # addr: (mangled_name, pp_name, addr, typ, calls: list[int])
        for f_addr, f in program.items():
            name = f.mangled_name
            if exports.get(f_addr) or exports.get(f_addr+1):  # If the function is somewhat exported (and visible in LIEF)
                res = exports.get(f_addr, exports.get(f_addr+1))
                canonical_name, all_names = res
                if name != canonical_name:
                    logging.info(f"change fun name: {name} -> {canonical_name}")
                    name = canonical_name  # In case of multiple names just select the canonical one

            _inter_cg[f_addr] = (name, f.name, f_addr, f.type, list(set(x.start for x in f.calls)))

        # Check if some exports don't have any associated function (not detected by IDA)
        for exp_addr in (exports.keys() - program.keys()):
            canon, allnames = exports[exp_addr]
            if p_fun := program.get(exp_addr-1):  # IDA keeps ARM address while LIEF use THUMB addresses
                if p_fun.mangled_name in allnames:  # Check that we have a match on names
                    continue
            # else case
            logging.info(f"export {canon}: {hex(exp_addr)} address not found in program (add one).")
            call_graph[canon] = []

        # Iterate back the temporary dict to fill the real call graph
        # The deal here is to fast-forward call to imported function directly on the imported
        # symbol and not on the PLT (to make the graph more straightforward)
        for f_name, f_pp_name, f_addr, f_type, calls in _inter_cg.values():

            if f_type in [FunctionType.NORMAL, FunctionType.LIBRARY]:
                call_graph[f_name] = []  # add entry in call graph

                # Iter calls (ignore calls that are not pointing to a function!)
                for c_name, c_pp_name, c_addr, c_type, c_calls in [_inter_cg[x] for x in calls if x in _inter_cg]:
                    if c_name:  # Has a true name
                        if c_type == FunctionType.THUNK and c_addr not in exports:
                            if len(c_calls) == 1:  # The callee calls something else (and only one)
                                sub_callee = _inter_cg[c_calls[0]] if c_calls[0] in _inter_cg else None
                                if sub_callee is None:
                                    continue  # Do don't anything if not pointing to a function
                                if sub_callee[3] in [FunctionType.IMPORTED, FunctionType.EXTERN]:
                                    call_graph[f_name].append(c_name)  # Keep the name of the thunk "strcpy, sprintf"
                                else:  # Forward the call to the underlying function name
                                    call_graph[f_name].append(sub_callee[0])
                            else:
                                call_graph[f_name].append(c_name)  # Add it normally
                        else:  # In all other cases
                            call_graph[f_name].append(c_name)  # Add it normally
                    else: # ignore function without name
                        logging.warning(f"[{program.name}] {f_name} calls a function without name (at {c_addr:#08x})")

            # If thunk AND exported still keep it (for later resolution)
            elif f_type == FunctionType.THUNK and ((f_addr in exports) or (f_addr+1 in exports)):
                call_graph[f_name] = [_inter_cg[x][0] for x in calls if x in _inter_cg]

            else:  # THUNK, IMPORTED, EXTERN (not included in call graph)
                pass

        # Change exports dict to be: name_mangled -> name_canonical
        exports = {name: x[0] for x in exports.values() for name in x[1]}

        # Add to demangled mapping, IDA functions names from Quokka
        demangled.update({x[0]: x[1] for x in _inter_cg.values()})

        return Binary(-1,
                      exec_file.name,
                      str(exec_file),
                      calls=call_graph,
                      exports=exports,
                      demangled=demangled)


    @staticmethod
    def get_lief_exports_mapping(exec_file) -> tuple[
                                        dict[int, tuple[str, list[str]]],
                                        dict[str, str]]:
        """
        Get the export mapping of a file as given by LIEF.

        :param exec_file: executable file to analyse
        :return: dictionary of  Address -> (favored_mangled_name, [mangled_names])
        """
        if not re.match(".*\.so(\.\d*)*$", str(exec_file)):
            return {}, {}  # Only gather exports for .so files. Assume none are exported for the other binaries

        p = lief.parse(exec_file)

        # Fill dict with exported symbols
        exports = defaultdict(list)  # list there can be multiple symbols on the same address
        for s in (s for s in p.symbols if s.is_function and s.exported):
            exports[s.value].append(s.name)  # !! Add mangled name !

        # Redefine exports mapping to choose a single name for all aliases
        exports = {k: (Binary.disambiguate_export(names), names) for k, names in exports.items()}

        demangled = {x.name: x.demangled_name for x in p.symbols if x.is_function and x.exported}
        return exports, demangled


    @staticmethod
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


if __name__ == "__main__":
    import sys
    file = sys.argv[1]
    print(file)
    binary = Binary.load_program(file+".quokka", file)

    symbol_ids = {}
    # Add all functions within the binary as function of the module
    for f_name, targets in binary.calls.items():
        pp_name = binary.demangled[f_name]
        # f_id = db.record_function(pp_name, parent_id=bin_id)  # register pp_name instead of mangled name
        symbol_ids[f_name] = 0

    # Iterate all exports to add additional (missing) export values in symbol_ids
    for exp_name, canonical_target in binary.exports.items():
        if exp_name not in symbol_ids:  # The export 'name' was not part of functions visible in IDA (so add it)
            n_id = symbol_ids[canonical_target]
            symbol_ids[exp_name] = n_id  # alias to the numbat_id
