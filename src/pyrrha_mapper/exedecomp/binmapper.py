import logging
import json
from pathlib import Path
from collections import namedtuple, defaultdict
from dataclasses import dataclass
from typing import Generator


# third-party imports
from quokka import Program, Function
from quokka.types import FunctionType
from numbat import SourcetrailDB
import magic
from idascript import IDA

DECOMPILE_SCRIPT = Path(__file__).parent / "decompile.py"

once_check = True

Location = namedtuple("Location", "start_line start_col end_line end_col")



@dataclass
class DecompiledFunction:
    address: int
    name: str  # demangled (pp_print)
    text: str
    location: Location  # location of the function name within text
    references: dict[int, list[Location]]  # callee_addr -> list(start_line, start_col, end_line, end_col)
    numbat_id: int = -1


def is_new_numbat(db: SourcetrailDB) -> bool:
    global once_check
    if hasattr(db, "change_node_color"):  # check that attribute but could have been another one
        return True
    else:
        if once_check:
            logging.warning("Numbat does not support advanced features")
            once_check = False
            return False



def normalize_name(name: str) -> str:
    """ Transform function name  """
    return name.strip("_").strip(".")


def find_all_call_references(f: Function, source: str) -> tuple[Location, dict[int, list[Location]]]:
    decl_loc = None
    refs = defaultdict(list)  # dict: call_addr -> list[Location]
    #ppname = lambda name: name.strip("_").strip(".")

    call_name_to_addr = {normalize_name(c.name): c.start for c in f.calls if c.name}  # NOTE: we exclude by design calls that
    call_addr_to_name = {c.start: normalize_name(c.name) for c in f.calls if c.name}  # don't have a name, usually these are calls
                                                                      # to unrecognized function e.g: loc_185CC
    for idx, line in enumerate(source.split("\n")):

        # try to find function declaration
        if decl_loc is None:
            ppname = normalize_name(f.name)
            col = line.find(normalize_name(f.name))
            if col != -1:
                decl_loc = Location(idx+1, col+1, idx+1, col+len(ppname))

        # # iterate each calls and try to find them in the line
        # for cname, caddr in call_name_to_addr.items():
        #     col = line.find(cname)
        #     if col != -1:
        #         refs[caddr].append(Location(idx+1, col+1, idx+1, col+len(cname)))

        # For a given line, this dict keeps the column (index) of all call matched
        matches: dict[int, tuple[int, str]] = {}

        # iterate each calls and try to find them in the line
        for cname, caddr in call_name_to_addr.items():
            col = line.find(cname)
            if col != -1:
                matches[col] = (caddr, cname)

        # Iterate all matches in a sorted manner to avoid having overlap matches:
        # e.g: If a function calls both lxstat() and xstat() for each line we search
        # any occurence of this two functions. But if we have a line like: "int c = lxstats()"
        # we will match both functions! Thus we sort them by the column index. In that case we
        # keep lxstats().
        sorted_matches = sorted(list(matches.items()), key=lambda x: x[0])
        cursor = 0
        previous = (0, '')
        while sorted_matches:
            col, (caddr, cname) = sorted_matches.pop(0)
            if col < cursor: # means the match is overlapping a previous match
                logging.warning(f"fun:{f.name} skip match {cname}[{col}] overlap with previous one {previous[0]}[{previous[1]}]")
            else:  # its okay we add it
                refs[caddr].append(Location(idx+1, col+1, idx+1, col+len(cname)))
                cursor = col+len(cname)
                previous = (col, cname)


    if decl_loc is None:
        logging.error(f"function declaration '{f.name}' not found in source code")
    for ref in (x for x in call_addr_to_name if x not in refs):
        logging.error(f"[{f.name}] call to {ref:#08x}:'{call_addr_to_name[ref]}' not found in source code")

    return decl_loc, refs


def decompile_program(program: Program) -> Path:
    """
    Generate a PROGRAM_NAME.decompiled file which contained the binary decompilee obtained
    with IDA.
    :param program: Program object of the file to decompiled
    :return: path of the created decompiled file
    """
    bin_path = program.executable.exec_file
    ida = IDA(bin_path,
              str(DECOMPILE_SCRIPT),
              [],
              timeout=180,
              exit_virtualenv=True)
    ida.start()
    ida.wait()
    return Path(str(bin_path)+".decompiled")



def load_decompiled(program: Program) -> dict[int, DecompiledFunction]:
    decompile_file = Path(str(program.executable.exec_file)+".decompiled")
    if decompile_file.exists():
        logging.info(f"load decompilation file: {decompile_file}")
        data = {int(k): v for k, v in json.loads(decompile_file.read_text()).items()}
        final_data = {}
        # Iterate the decompiled data to try make references inside
        for f_addr, source_text in data.items():
            f = program[f_addr]

            decl, refs = find_all_call_references(f, source_text)

            final_data[f_addr] = DecompiledFunction(
                address=f_addr,
                name=f.name,
                text=source_text,
                location=decl,
                references=refs
            )

        return final_data
    else:
        logging.info("extracting decompilation file (with idascript)")
        decompile_file = decompile_program(program)
        if decompile_file.exists():
            return load_decompiled(program)  # call ourselves again
        else:
            logging.warning("can't find decompilation file and idascript failed")
            return {}


def load_program(bin_path: Path) -> Program:
    quokka_file = Path(f"{bin_path}.quokka")
    if quokka_file.exists():
        logging.info("loading existing Quokka file")
        return Program(quokka_file, bin_path)
    else:  # Quokka file does not exists
        return Program.from_binary(bin_path, quokka_file)



def set_function_color(db: SourcetrailDB, p: Program, fun: Function, f_id: int) -> None:
    if is_new_numbat(db):  # Check that we have the capability
        # Change node color based on its type
        if is_thunk_to_import(p, fun):
            db.change_node_color(f_id, fill_color="#bee0af", border_color="#395f33")
        elif fun.type == FunctionType.THUNK:
            db.change_node_color(f_id, fill_color="gray")
        # elif fun.type == FunctionType.EXTERN:
        #     db.change_node_color(f_id, fill_color="magenta")
        # elif fun.type == FunctionType.IMPORTED:
        #     db.change_node_color(f_id, fill_color="mediumvioletred")
        else:
            pass  # Normal function let default color
    else:
        return


def add_source_file(db: SourcetrailDB, mangled_name: str, symbol_id: int, info: DecompiledFunction) -> bool:
    tmp = Path("/tmp/"+mangled_name)
    with open(tmp, "w") as f:
        f.write(info.text)

    # Record file
    file_id = db.record_file(Path(tmp)) #, indexed=False)
    if file_id is None:
        return False
    db.record_file_language(file_id, 'cpp')
    tmp.unlink()  # QUESTION: Maybe we want to keep it for further analyses ?

    # Add the function to the file
    logging.info(f"add function {mangled_name} to file {file_id}")
    info.numbat_id = file_id
    # record de symbol declaration
    if info.location:
        l1, col1, l2, col2 = info.location
        db.record_symbol_location(symbol_id, file_id, l1, col1, l2, col2)
    else:
        logging.warning(f"{f.name} declaration not found in source code")

    return True

def is_thunk_to_import(p: Program, f: Function) -> bool:
    if f.type == FunctionType.THUNK:
        if len(f.calls) == 1:
            c = f.calls[0]
            callee = p.get_function_by_chunk(c)[0]
            if callee.type in [FunctionType.EXTERN, FunctionType.IMPORTED]:
                return True
        return False
    else:
        return False


def map_binary(db: SourcetrailDB, program_path: Path) -> bool:

    # Load the Quokka file
    program = load_program(program_path)
    if program is None:
        logging.error(f"can't generate exported binary")
        return False

    # Load the decompilation file
    decompiled = load_decompiled(program)
    if not decompiled: # empty
        logging.error(f"failed to obtain decompiled code")
        return False

    # Index all the functions
    f_mapping = {}  # f_addr -> numbat_id
    for f_addr, f in program.items():
        logging.info(f"============= process: {f.name} {f.type} =============")
        if f.type in [FunctionType.EXTERN, FunctionType.IMPORTED]:
            logging.info(f"skip {f.name} extern function")
            continue  # do not add EXTERN functions
        is_imp = is_thunk_to_import(program, f)
        f_id = db.record_function(f.name, parent_id=None) #, hover_display=f"{f.type.name.lower()} function")
        f_mapping[f_addr] = f_id

        # Change node color based on its type
        set_function_color(db, program, f, f_id)

        # Add custom command to open that function in IDA
        abs_path = program.executable.exec_file.absolute()
        cmd = ["ida64", f"-ONumbatJump:{f_addr:#08x}", str(abs_path)]
        db.set_custom_command(f_id, cmd, "Open in IDA Pro")

        # Add source code if any
        if f_addr in decompiled and not is_imp:
            info = decompiled[f_addr]
            if not add_source_file(db, f.mangled_name, f_id, info):
                logging.warning(f"failed to add decompiled code for: {f.name}")
        else:
            if f.type not in [FunctionType.EXTERN, FunctionType.IMPORTED]:
                logging.warning(f"function {f.name} not in decompiled dict")

    # Index the call graph
    logging.info("============= start indexing call graph =============")
    for f_addr, f in program.items():
        decomp_fun = decompiled.get(f_addr, None)

        for callee in f.calls:
            try:
                callee_id = f_mapping[callee.start]
                db.record_ref_call(f_mapping[f_addr], callee_id)  # record the call

                if decomp_fun:  # if we have info about the decompiled function
                    if refs := decomp_fun.references.get(callee.start):  # get the refs associated with callee
                        for li, coli, le, cole in refs:  # iterate them and add them
                            db.record_reference_location(callee_id, decomp_fun.numbat_id, li, coli, le, cole)
                    else:
                        logging.warning(f"{f.name} calls {callee.name} but not references in DecompiledFunction")

            except KeyError:
                pass  # ignore call to non recognized functions

    return True
