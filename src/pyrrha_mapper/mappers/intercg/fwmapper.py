import json
import logging
from collections import defaultdict
from pathlib import Path

from numbat import SourcetrailDB
from pyrrha_mapper.types import ResolveDuplicateOption
from rich.progress import Progress, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn

from .binary import Binary
from .pyrrha_dump import PyrrhaDump

IGNORE_LIST = ["__gmon_start__"]

QUOKKA_EXT = ".quokka"


def load_file_system(dump: PyrrhaDump, root_path: Path) -> list[Binary]:
    tot = len(dump.bin_by_path)

    all_bins = []

    for i, (pyr_id, bin_entry) in enumerate(dump.data["binaries"].items()):
        bin_path = bin_entry["path"]

        rel_bin = str(bin_path[1:] if bin_path.startswith("/") else bin_path)
        quokka_file = root_path / (rel_bin + QUOKKA_EXT)
        exec_file = root_path / rel_bin
        s = "SKIP" if not exec_file.exists() else ("LOAD" if quokka_file.exists() else "CREATE")
        logging.info(f"[{i+1}/{tot}] process: {bin_path} [{s}]")
        if not exec_file.exists():
            logging.error(f"cannot find executable file mentioned in 'fs' mapper: {exec_file.name} (skip)")
            continue
        if exec_file.suffix == ".ko":  # ignore kernel modules at the moment
            logging.warning("do not map kernel modules at the moment (skip)")
            continue
        try:
            binary = Binary.load_program(quokka_file, exec_file)
        except SyntaxError:
            logging.error(f"cannot load Quokka files: {quokka_file}")
            continue

        binary.pyrrha_id = int(pyr_id)
        binary.path = bin_path  # only keep relative path to FS root
        all_bins.append(binary)

    return all_bins


def make_export_to_binaries_map(all_bins: list[Binary]) -> dict[str, list[Binary]]:
    """
    Compute dict mapping: exported-funs -> binaries (exporting the function)
    Indeed multiple binaries can export the same symbol !
    """
    table = defaultdict(list)  # list there can be multiple symbols on the same address
    for binary in all_bins:
        for export in binary.exports:
            table[export].append(binary)
    return table


def load_binaries(root_path: Path, dump: PyrrhaDump, cache_file: Path) -> list[Binary]:
    """
    Load all the binaries located in the filesystem as Binary objects.

    :param root_path: root directory of the filesystem
    :param dump: Pyrrha dump
    :param cache_file: Cache file to load binaries from (if exists)
    :return: list of Binary objects
    """
    if cache_file.exists():
        logging.info(f"Load cached binaries: {cache_file.name}")
        data = json.loads(cache_file.read_text())
        return [Binary(*x.values()) for x in data]
    else:  # Otherwise load files from the filesystem
        all_bins = load_file_system(dump, root_path)
        logging.debug(f"Store cached binaries: {cache_file}")
        cache_file.write_text(json.dumps([x.to_dict() for x in all_bins]))
        return all_bins


def map_firmware(
    db: SourcetrailDB, root_path: Path, dump: PyrrhaDump, jobs: int, resolver: ResolveDuplicateOption
) -> bool:

    # Change some headers
    db.set_node_type("class", "Binaries", "binary")

    binary_mapping: dict[int, Binary] = {}  # pyrrha_id -> Binary
    pid_to_nid: dict[int, int] = {}  # pyrrha_id -> numbat_id
    symbol_ids = {}  # (binary) numbat_id -> function name -> (symbol function) numbat_id

    # Load binaries from the filesystem (or cache file)
    cache_file = db.path.with_suffix(".bins.json")
    all_bins = load_binaries(root_path, dump, cache_file)

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    ) as progress:
        binaries_map = progress.add_task("[deep_pink2]Binaries mapping", total=len(all_bins))

        # ---------- Iterate all binaries and add Nodes in the database ---------
        for i, binary in enumerate(all_bins):
            logging.debug(f"[{i + 1}/{len(all_bins)}] index node: {binary.name}")

            # Create the node entry in numbat
            bin_id = db.record_class(binary.path)  # record the path
            pid_to_nid[binary.pyrrha_id] = bin_id  # fill pyrrha_id -> numbat_id
            binary_mapping[binary.pyrrha_id] = binary  # fill index by pyrrha_id

            # Add custom command to open the sub-DB
            # abs_path = Path(str(root_path) + binary.path).absolute()
            # cmd = ["NumbatUi", str(abs_path)+".srctrlprj"]
            # db.set_custom_command(bin_id, cmd, "Open in NumbatUI")
            # -----------------

            symbol_ids[bin_id] = {}
            # Add all functions within the binary as function of the module
            for f_name in binary.calls.keys():
                pp_name = binary.demangled[f_name]
                f_id = db.record_function(pp_name, parent_id=bin_id)  # register pp_name instead of mangled name
                symbol_ids[bin_id][f_name] = f_id

                if f_name in binary.exports:  # Change if exported
                    db.change_node_color(
                        f_id, fill_color="#bee0af", border_color="#395f33"
                    )  # text_color="brown", icon_color="brown", hatching_color="#FFEBCD")

            # Iterate all exports to add additional (missing) export values in symbol_ids
            for exp_name, canonical_target in binary.exports.items():
                if (
                    exp_name not in symbol_ids[bin_id]
                ):  # The export 'name' was not part of functions visible in IDA (so add it)
                    n_id = symbol_ids[bin_id][canonical_target]
                    symbol_ids[bin_id][exp_name] = n_id  # alias to the numbat_id

            progress.update(binaries_map, advance=1)
        # ---------------------------------------------------------------

        # Compute reverse-lookup table of:  exported-funs -> [binaries]
        table = make_export_to_binaries_map(all_bins)

        # Iterate again all binaries to create call edges (all numbat_id are created)
        tot = len(binary_mapping)
        cg_map = progress.add_task("[orange1]Call Graph mapping", total=len(all_bins))

        for i, (pyr_id, binary) in enumerate(binary_mapping.items()):
            resolve_cache = set()
            num_id = pid_to_nid[binary.pyrrha_id]

            logging.debug(
                f"-------------- [{i+1}/{tot}] index call graph {binary.path} [pyr_id:{pyr_id}] --------------"
            )

            # Create mapping of external functions
            deps_symbols = {}  # fun_name -> numbat_id
            for dep_pyr_id in dump.get_dependencies(pyr_id).keys():
                # need to convert pyr_id to num_id
                dep_num_id = pid_to_nid[dep_pyr_id]
                deps_symbols.update(symbol_ids[dep_num_id])

            cur_syms = symbol_ids[num_id]

            good, bad = 0, 0
            for f_name, targets in binary.calls.items():
                targets = targets[:]
                while targets:
                    target = targets.pop()
                    try:
                        if target in binary.calls:  # local call
                            tgt = cur_syms[target]
                            db.record_ref_call(cur_syms[f_name], tgt)
                            good += 1
                        elif target in deps_symbols:
                            tgt = deps_symbols[target]
                            db.record_ref_call(cur_syms[f_name], tgt)
                            good += 1
                        else:
                            if target not in IGNORE_LIST:
                                served_by: list[Binary] = table[target]  # sert à quoi ?

                                if len(served_by) > 1 and resolver == ResolveDuplicateOption.INTERACTIVE:
                                    print(f"cache: {[x.path for x in resolve_cache]}")
                                    for cache_entry in resolve_cache:
                                        if cache_entry in served_by:  # reuse already selected entry
                                            logging.debug(f"reuse manually selected entry to disambiguate {target}")
                                            served_by = [cache_entry]
                                    if len(served_by) > 1:  # still not resolved
                                        print(f"symbol {target} needed for {binary.path} served by multiple binaries:")

                                        for num, option in enumerate(table[target]):
                                            print(f"* [{num}] {option.path}")

                                        res = input("Select (default=0): ")
                                        val = 0 if not res else int(res)
                                        choice_bin = table[target][val]
                                        resolve_cache.add(choice_bin)
                                        served_by = [choice_bin]
                                elif resolver == ResolveDuplicateOption.ARBITRARY:
                                    arb_choice = table[target][0]
                                    resolve_cache.add(arb_choice)
                                    served_by = [arb_choice]  # Take the first one

                                if len(served_by) == 1:  # Automatically add the lib to deps_symbols
                                    logging.debug(
                                        f"symbol {target} served by {served_by[0].name} automatically add it!"
                                    )
                                    deps_symbols.update(symbol_ids[pid_to_nid[served_by[0].pyrrha_id]])
                                    targets.append(target)  # Push back the target to try again
                                else:  # if still not resolved
                                    bad += 1
                                    logging.warning(
                                        f"can't resolve edge: {f_name} -> {target}: provided by {[x.name for x in table[target]] if target in table else '[EMPTY]'}"
                                    )
                    except KeyError as e:
                        logging.error(f"can't find symbols: {e}")
            logging.debug(f"Good: {good}, Bad: {bad}")
            progress.update(cg_map, advance=1)
    return True
