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
"""Decompilation code binary mapper."""

import logging
import json
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
import sys
from typing import NamedTuple
from tempfile import NamedTemporaryFile
import hashlib

# third-party imports
from qbinary import Program, Function, FunctionType
from qbinary.types import Disassembler, ExportFormat, DisassExportNotImplemented, ExportException


from numbat import SourcetrailDB
from idascript import IDA
from numbat import SourcetrailDB
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

# local imports
from pyrrha_mapper.exceptions import FsMapperError

DECOMPILE_SCRIPT = Path(__file__).parent / "decompile.py"

# Determine the command to open URLs based on the platform
try:
    URL_OPEN_CMD = {
        "linux": "xdg-open",
        "win32": "start",
        "darwin": "open"
    }[sys.platform]
except KeyError:
    logging.warning(f"Unsupported platform: {sys.platform} (will not add URL handler)")
    URL_OPEN_CMD = "" # type: ignore


once_check = True



class Location(NamedTuple):
    start_line: int
    start_col: int
    end_line: int
    end_col: int


@dataclass
class DecompiledFunction:
    """Class used to represent a decompiled function."""

    address: int
    name: str  # demangled (pp_print)
    text: str
    location: Location  # location of the function name within text
    references: dict[
        int, list[Location]
    ]  # callee_addr -> list(start_line, start_col, end_line, end_col)
    numbat_id: int = -1


def normalize_name(name: str) -> str:
    """Transform function name."""
    return name.strip("_").strip(".")


def find_all_call_references(p:Program, f: Function, source: str,
                             log_prefix: str = "") -> tuple[Location, dict[int, list[Location]]]:
    decl_loc = None
    refs: dict[int, list[Location]] = defaultdict(list)  # dict: call_addr -> list[Location]
    #ppname = lambda name: name.strip("_").strip(".")

    # NOTE: we exclude by design calls that don't have a name, usually these are calls
    # to unrecognized function e.g: loc_185CC
    call_name_to_addr = {normalize_name(p[c].name): c for c in f.children if p[c].name}
    call_addr_to_name = {c: normalize_name(p[c].name) for c in f.children if p[c].name}


    for idx, line in enumerate(source.splitlines()):
        # try to find function declaration
        if decl_loc is None:
            ppname = normalize_name(f.name)
            col = line.find(normalize_name(f.name))
            if col != -1:
                decl_loc = Location(idx + 1, col + 1, idx + 1, col + len(ppname))

        # For a given line, this dict keeps the column (index) of all call matched
        matches: dict[int, tuple[int, str]] = {}

        # iterate each calls and try to find them in the line
        for cname, caddr in call_name_to_addr.items():
            if cname.endswith(")"): # to handle cases of func name with typing of parameter 
                name = cname.split("(")[0]
            else:
                name = cname
            col = line.find(f"{name}(")
            if col != -1:
                matches[col] = (caddr, cname)

        # Iterate all matches in a sorted manner to avoid having overlap matches:
        # e.g: If a function calls both lxstat() and xstat() for each line we search
        # any occurence of this two functions. But if we have a line like: "int c = lxstats()"
        # we will match both functions! Thus we sort them by the column index. In that case we
        # keep lxstats().
        sorted_matches = sorted(list(matches.items()), key=lambda x: x[0])
        cursor = 0
        previous = (0, "")
        while sorted_matches:
            col, (caddr, cname) = sorted_matches.pop(0)
            if col < cursor:  # means the match is overlapping a previous match
                if col + len(cname) == cursor and previous[1].endswith(cname):
                    logging.debug(f"{log_prefix}: skip match {cname}, end of the {previous[1]}")
                else:
                    logging.warning(
                        f"{log_prefix}: skip match {cname} [col {col}] overlap with previous one  "
                        f"{previous[1]} [col: {previous[0]}]"
                    )
            else:  # its okay we add it
                refs[caddr].append(Location(idx + 1, col + 1, idx + 1, col + len(cname)))
                cursor = col + len(cname)
                previous = (col, cname)

    if decl_loc is None:
        logging.error(f"{log_prefix}: function declaration not found in source code")

    if not is_thunk_to_import(p, f):  # it is normal no to find the call in thunks to imports
        for ref in (x for x in call_addr_to_name if x not in refs):
            logging.warning(f"{log_prefix}: call to {ref:#08x}: '{call_addr_to_name[ref]}' not found in source code")

    return decl_loc, refs


def decompile_program(program: Program) -> None:
    """Generate a PROGRAM_NAME.decompiled file which contained the binary decompilee obtained with IDA.

    :param program: Program object of the file to decompiled
    :return: path of the created decompiled file.
    """
    bin_path: str = program.exec_path
    assert bin_path, "program.exec_path is not set, can't decompile"
    ida = IDA(bin_path, str(DECOMPILE_SCRIPT), [], timeout=600, exit_virtualenv=True)
    ida.start()
    ida.wait()


def load_decompiled(program: Program, progress: Progress,
                    log_prefix: str = "") -> dict[int, DecompiledFunction]:
    decompile_file = Path(f"{program.exec_path}.decompiled")

    if decompile_file.exists():
        logging.info(f"{log_prefix}: load file: {decompile_file}")
        data = {int(k): v for k, v in json.loads(decompile_file.read_text()).items()}
        final_data: dict[int, DecompiledFunction] = {}
        # Iterate the decompiled data to try make references inside
        decomp_load = progress.add_task("[deep_pink2]Decompiled binary loading", total=len(data))
        for f_addr, source_text in data.items():
            f: Function = program.get(f_addr)
            if f is None:
                logging.warning(f"{log_prefix}: function at {f_addr:#08x} referenced "
                                "in decompiled code not found in exported program")
                continue

            decl, refs = find_all_call_references(program, f, source_text, f"{log_prefix} {f.name}")

            assert decl is not None, f"function {f.name} declaration not found in source code"

            final_data[f_addr] = DecompiledFunction(
                address=f_addr, name=f.name, text=source_text, location=decl, references=refs
            )
            progress.update(decomp_load, advance=1)

        return final_data
    else:
        logging.info(f"{log_prefix}: extracting decompilation file {decompile_file} (with idascript)")
        decompile_program(program)
        if decompile_file.exists():
            return load_decompiled(program, progress, log_prefix)  # call ourselves again
        else:
            raise FileNotFoundError("can't find decompilation file (idascript failed)")


def load_program(bin_path: Path, disass: Disassembler, format: ExportFormat) -> Program | None:
    # First try to find pre-existing exported files if format is AUTO
    try:
        return Program.from_binary(bin_path,
                                   export_format=format,
                                   disassembler=disass,
                                   timeout= 600,  # TODO: Receive through command line ?
                                   override=False,  # if export exists use it
        )
    except DisassExportNotImplemented as e:
        logging.error(f"Disassembler {disass} does not support export format {format}: {e}")
    except ExportException as e:
        logging.error(f"Error while loading binary {bin_path}: {e}")
    return None


def set_function_color(db: SourcetrailDB, p: Program, fun: Function, f_id: int) -> None:
    # Change node color based on its type
    if is_thunk_to_import(p, fun):
        db.change_node_color(f_id, fill_color="#bee0af", border_color="#395f33")
    elif fun.type == FunctionType.thunk:
        db.change_node_color(f_id, fill_color="gray")
    # elif fun.type == FunctionType.EXTERN:
    #     db.change_node_color(f_id, fill_color="magenta")
    # elif fun.type == FunctionType.IMPORTED:
    #     db.change_node_color(f_id, fill_color="mediumvioletred")
    else:
        pass  # Normal function let default color


def add_source_file(
    db: SourcetrailDB,
    mangled_name: str,
    symbol_id: int,
    info: DecompiledFunction,
    log_prefix: str = "",
) -> bool:
    """:return: True if successfully added source info.text as a source file in DB."""
    with NamedTemporaryFile(mode="wt", delete_on_close=True) as tmp:
        tmp.write(info.text)
        tmp.flush()  # Ensure the file is written before we try to record it
        # Record file
        file_id = db.record_file(Path(tmp.name), name=mangled_name)
        if file_id is None:
            return False
        db.record_file_language(file_id, "cpp")
        tmp.close()

    # Add the function to the file
    logging.debug(f"{log_prefix}: add function {mangled_name} to file {file_id}")
    info.numbat_id = file_id
    # record de symbol declaration
    if info.location:
        l1, col1, l2, col2 = info.location
        db.record_symbol_location(symbol_id, file_id, l1, col1, l2, col2)
    else:
        logging.warning(f"{log_prefix}: declaration not found in source code")

    return True


def is_thunk_to_import(p: Program, f: Function) -> bool:
    if f.type == FunctionType.thunk:
        if len(f.children) == 1:
            c = list(f.children)[0]
            callee: Function = p[c]
            if callee.type == FunctionType.imported:
                return True
        return False
    else:
        return False


def add_url_handler(db: SourcetrailDB, program: Program, hash: str, function: Function, f_id: int) -> None:
    """ Open the function using a dedicated URL handler. (Use Heimdallr) """
    if URL_OPEN_CMD and program.exec_path:
        url = f"disas://{hash}?idb={Path(program.exec_path).name+'.i64'}&offset={function.addr:#08x}"
        cmd: list[str] = [URL_OPEN_CMD, url]
        db.set_custom_command(f_id, cmd, "Open in Disassembler") # type: ignore
    else:
        pass  # Can't add URL unsuported platform


def map_binary(db: SourcetrailDB, program_path: Path, disass: Disassembler, format: ExportFormat) -> bool:
    # Load the Quokka file
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    ) as progress:
        # Load the decompilation and quokka files
        log_prefix = "[binary loading]"
        try:
            program = load_program(program_path, disass, format)
            if program is None:
                logging.error(f"{log_prefix} can't generate exported binary")
                return False
        except FileNotFoundError as e:
            logging.error(f"{log_prefix}: Cannot found {program_path}: {e}")
            return False
        except FsMapperError as e:
            logging.error(f"{log_prefix}: Error during Quokka export generation/loading: {e}")
            return False

        # Try loading the decompiled file
        try:
            decompiled = load_decompiled(program, progress, log_prefix)
        except FileNotFoundError as e:
            logging.error(f"{log_prefix}: failed to obtain decompiled code: {e}")
            return False

        # Compute MD5 hash for URL handler
        p_hash = hashlib.md5(Path(program.exec_path).read_bytes()).hexdigest()

        # Index all the functions
        f_mapping = {}  # f_addr -> numbat_id
        func_map = progress.add_task("[orange_red1]Functions analysis", total=len(program))
        for f_addr, f in program.items():
            log_prefix = f"[func analysis] {f.name} ({f.type})"
            if f.type == FunctionType.imported:
                logging.debug(f"{log_prefix}: extern function, skip")
                progress.update(func_map, advance=1)
                continue  # do not add EXTERN functions
            is_imp = is_thunk_to_import(program, f)
            f_id = db.record_function(f.name, parent_id=None, is_indexed=not is_imp)
            if f_id is None:
                logging.error(f"{log_prefix}: error while recording function in db")
                progress.update(func_map, advance=1)
                continue
            f_mapping[f_addr] = f_id

            # Change node color based on its type
            set_function_color(db, program, f, f_id)

            # Add custom command to open that function in IDA
            add_url_handler(db, program, p_hash, f, f_id)

            # Add source code if any
            if f_addr in decompiled and not is_imp:
                info = decompiled[f_addr]
                if not add_source_file(db, f.mangled_name, f_id, info):
                    logging.warning(f"{log_prefix}: failed to add decompiled code")
            elif f_addr not in decompiled and not is_imp:
                logging.warning(f"{log_prefix}: function not in decompiled dict")
            else:
                pass # do not add decompiled code for thunks to imports

            progress.update(func_map, advance=1)


        # Index the call graph
        cg_map = progress.add_task("[orange1]Call Graph Indexing", total=len(program))

        for f_addr, f in program.items():
            log_prefix = f"[callgraph indexing] {f.name}"
            decomp_fun = decompiled.get(f_addr, None)

            for callee in f.children:
                try:
                    callee_id = f_mapping[callee]
                    db.record_ref_call(f_mapping[f_addr], callee_id)  # record the call

                    if decomp_fun:  # if we have info about the decompiled function
                        if refs := decomp_fun.references.get(callee):  # get the refs associated with callee
                            for li, coli, le, cole in refs:  # iterate them and add them
                                db.record_reference_location(callee_id, decomp_fun.numbat_id, li, coli, le, cole)
                        else:
                            logging.warning(f"{log_prefix} calls {program[callee].name} "
                                            "but not references in DecompiledFunction")

                except KeyError:
                    pass  # ignore call to non recognized functions

            progress.update(cg_map, advance=1)
    return True
