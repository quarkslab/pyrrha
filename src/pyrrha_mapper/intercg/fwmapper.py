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
"""InterCGMapper implementation."""

import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

# third-party imports
from numbat import SourcetrailDB
from rich.progress import Progress

# local imports
from pyrrha_mapper.common import (
    Binary,
    FileSystem,
    Symbol,
    Symlink,
    hide_progress,
)
from pyrrha_mapper.exceptions import FsMapperError
from pyrrha_mapper.fs import FileSystemImportsMapper
from pyrrha_mapper.intercg.loader import BinaryParser, GhidraParser, IDAParser
from pyrrha_mapper.types import Backend, ResolveDuplicateOption

IGNORE_LIST: frozenset[str] = frozenset(
    [
        # Linker-injected bookkeeping stubs
        "__gmon_start__",
        "_ITM_deregisterTMCloneTable",
        "_ITM_registerTMCloneTable",
        "__TMC_END__",
        "deregister_tm_clones",
        "register_tm_clones",
        # ITM runtime helpers
        "_ITM_RU1",
        "_ITM_addUserCommitAction",
        "_ITM_memcpyRnWt",
        "_ITM_memcpyRtWn",
        # C++ operators (Ghidra partial-demangle form)
        "operator new",
        "operator new[]",
        "operator delete",
        "operator delete[]",
        "new[]",
        "operator==",
        "operator!=",
        "operator<",
        "operator>",
        "operator<=",
        "operator>=",
        "operator=",
        "operator+",
        "operator-",
        "operator*",
        "operator/",
        "operator[]",
        "operator()",
        "operator<<",
        "operator>>",
        "operator+=",
        "operator-=",
        # GCC exception helpers — never valid cross-binary callees
        "__throw_bad_alloc",
        "__throw_bad_array_new_length",
        "__throw_bad_cast",
        "__throw_bad_function_call",
        "__throw_future_error",
        "__throw_invalid_argument",
        "__throw_length_error",
        "__throw_logic_error",
        "__throw_out_of_range",
        "__throw_out_of_range_fmt",
        "__throw_overflow_error",
        "__throw_range_error",
        "__throw_regex_error",
        "__throw_runtime_error",
        "__throw_system_error",
        "__throw_underflow_error",
        # C++ ABI internal
        "__do_upcast",
    ]
)

# Tool-generated synthetic names (FUN_<HEX>, _INIT_<N>, _FINI_<N>) that can
# never be resolved as cross-binary callees.
_GHIDRA_SYNTHETIC_NAME_RE: re.Pattern[str] = re.compile(
    r"^(?:FUN_[0-9A-Fa-f]+|_INIT_\d+|_FINI_\d+)$"
)

NUMBAT_UI_BIN = "NumbatUi"


class InterImageCGMapper(FileSystemImportsMapper):
    """Filesystem mapper based on Lief, which computes imports and exports."""

    FS_EXT = ".fs.json"

    def __init__(
        self,
        root_directory: Path | str,
        db: SourcetrailDB | None,
        backend: Backend,
    ):
        super(InterImageCGMapper, self).__init__(root_directory, db)
        # super initialize root_directory, db_interface, fs and _dry_run variables

        # override fs with the one provided by the fs_mapper (in dry-mode)
        # it should not contains any id

        if not self.dry_run_mode and self.db_interface is not None:
            # Change some headers
            self.db_interface.set_node_type("class", "Binaries", "binary")

        # Mapping to keep Numbat ID to the associated object
        self.node_ids: dict[int, Binary | Symbol | Symlink] = {}
        # Mapping to keep export_name -> list[Binary] exposing this function
        self.exports_to_bins: dict[str, list[Binary]] = {}
        self.progress: Progress | None = None
        self.unresolved_callgraph: dict[Path, dict[Symbol, list[str]]] = dict()
        self.backend = backend

    def _correct_map_result(self, res: Any) -> bool:
        return (
            super()._correct_map_result(res)
            and len(res) == 2
            and isinstance(res[1], dict)
            and all(
                map(  # correct equivalent to `isinstance(data, dict[Symbol, list[str]])`
                    lambda x: isinstance(x[0], Symbol) and self._is_list_str(x[1]),
                    res[1].items(),
                )
            )
        )

    def load_binary_args(self) -> dict[str, Any]:
        """Return dict of args for load_binary that are always the same for the wholde firmware.

        Use to optimize multiprocessing. Set here there real values.
        """
        res = super().load_binary_args()
        res["backend"] = self.backend
        return res

    @staticmethod
    def load_binary(
        root_directory: Path,
        file_path: Path,
        backend: Backend = Backend.IDA,
    ) -> tuple[Binary, dict[Symbol, list[str]] | None] | str:
        """Load all the binaries located in the filesystem as Binary objects.

        First check if a cache file exists, if yes, it will load all the binaries and
        their analysis from it.
        Otherwhise, it take a FileSystem object generated by FS-mapper and
        enrich it with InterCG-mapper required data. It includes call graphs
        and some function normalization in case collisions. It modifies the
        FileSystem object in place.
        """
        try:
            if backend == Backend.IDA:
                ida_parser: BinaryParser = IDAParser(root_directory, file_path)
                return ida_parser.binary, ida_parser.call_graph
            elif backend == Backend.GHIDRA:
                ghidra_parser = GhidraParser(root_directory, file_path)
                return ghidra_parser.binary, ghidra_parser.call_graph
            else:
                return f" disassembler {backend} is not supported"
        except (FileNotFoundError, FsMapperError, SyntaxError) as e:
            return f"[binary mapping] {file_path.name}: ERROR: Loading error: {e}"

    def map_binary(
        self,
        bin_object: Binary,
        additional_res: dict[Symbol, list[str]] | None = None,
    ) -> None:
        """Given a Binary object add it to the DB.

        This function updates the filesystem representation stored as `self.fs`.
        :param bin_object: Binary object
        """
        super().map_binary(bin_object)
        if additional_res is not None:
            self.unresolved_callgraph[bin_object.path] = additional_res
        if bin_object.id is not None:
            self.node_ids[bin_object.id] = bin_object
            if additional_res is not None:
                self._record_custom_command(bin_object, f"[bin mapping] {bin_object.name}")

    def _treat_bin_parsing_result(self, path: Path, res: Any):
        """Handle load_binary res, map it or display error."""
        log_prefix = f"[binary parsing] {path.name}"
        if isinstance(res, str):
            logging.error(f"{log_prefix}: {res}")
        elif isinstance(res, BaseException):
            logging.error(f"{log_prefix}: {repr(res)}")
        elif self._correct_map_result(res):
            bin_obj, additional_info = res
            self.map_binary(bin_obj, additional_info)
        elif super()._correct_map_result(res):
            self.map_binary(res[0], None)
            logging.info(f"{log_prefix}: fallback to lief results, internal analysis failed")
        else:
            logging.warning(f"{log_prefix}: impossible to parse the following result {res.args}")

    @staticmethod
    def _merge_parser_functions_into_cached_binary(
        parser_bin: Binary, cached_bin: Binary, log_prefix: str = ""
    ) -> None:
        """Merge disassembler-discovered functions from *parser_bin* into *cached_bin*.

        The .fs.json cache only contains LIEF-visible data.  After a cache
        reload the disassembler is re-run to rebuild the call graph, but the
        resulting ``Binary`` object (``parser_bin``) is discarded — only the
        cached binary (``cached_bin``) stays in ``self.fs``.  This means that
        any function the disassembler registered that was not already present in
        the LIEF binary (e.g. internal functions discovered via ``add_function``
        during ``_combine_program_analysis_binary``) will be absent from
        ``cached_bin``.  The CG mapping loop then hits
        ``not binary.function_exists(f_symb.name)`` for every such function and
        silently drops the associated call edges.

        This helper bridges the gap by:

        1. Registering internal functions present in ``parser_bin`` but absent
           from ``cached_bin``.  These functions have no DB id (they were never
           recorded in Numbat), which is correct — only exported symbols are
           recorded.
        2. Registering exported functions present in ``parser_bin`` but absent
           from ``cached_bin``.  This handles symbols the disassembler promoted
           to exports that LIEF did not see.  No DB id is assigned.

        The operation is intentionally conservative: it never removes existing
        functions from ``cached_bin`` and never overwrites a symbol that already
        has an id.

        :param parser_bin: freshly-parsed Binary produced by the disassembler.
        :param cached_bin: Binary loaded from the .fs.json cache (has DB ids).
        :param log_prefix: prefix for log messages.
        """
        # Step 1 — register internal functions discovered only by the disassembler.
        for func_name, func_symb in parser_bin.internal_functions.items():
            if not cached_bin.function_exists(func_name):
                cached_bin.add_function(func_symb, func_name=func_name)
                logging.debug(
                    f"{log_prefix}: merged internal function '{func_name}' from parser into cache"
                )

        # Step 2 — ensure the cached binary's exported function set is a
        # superset of the parser's.  Symbols exported by the disassembler but
        # absent from the cached binary are added so function_exists() succeeds.
        # No DB id is assigned — these symbols were not recorded in Numbat.
        for func_name, func_symb in parser_bin.exported_functions.items():
            if not cached_bin.exported_function_exists(func_name):
                cached_bin.add_exported_symbol(func_symb, symbol_name=func_name)
                logging.debug(
                    f"{log_prefix}: merged exported function '{func_name}' from parser into cache"
                )

    def map_binaries_main(self, threads: int, progress: Progress) -> None:
        """Parse and map binaries of a given directory.

        Record them in self.fs and self.db (except if self.is_dry_run == True).
        :param threads: number of threads to use
        :param progress: a rich.progress bar object for cli rendering
        """
        if self.dry_run_mode or self.db_interface is None:
            cache_file = None
        else:
            cache_file = self.db_interface.path.with_suffix(self.FS_EXT)

        # if cache exists, load binaries from it and record them in DB
        if cache_file is not None and cache_file.exists():
            logging.info(f"[binary mapping]: Load cached binaries: {cache_file.name}")
            self.fs = FileSystem.from_json_export(cache_file)
            binaries_map = progress.add_task(
                "[red]Binaries recording", total=len(list(self.fs.iter_binaries()))
            )
            # The .fs.json cache only serialises LIEF-visible data.  The
            # disassembler call graph is transient and internal functions
            # discovered by the disassembler (absent from LIEF's symbol table)
            # are not persisted either.  We must therefore:
            #   1. Re-run the disassembler for each binary to rebuild
            #      unresolved_callgraph and recover internal functions.
            #   2. Merge those internal functions into the cached Binary
            #      BEFORE calling record_binary_in_db, so that Numbat receives
            #      DB ids for them.  Without ids, _record_call_ref silently
            #      drops every call whose caller is an internal function.
            for binary in self.fs.iter_binaries():
                log_prefix = f"[bin mapping] {binary.name}"
                if binary.real_path is not None:
                    res = self.load_binary(file_path=binary.real_path, **self.load_binary_args())
                    if isinstance(res, str):
                        logging.error(f"{log_prefix}: CG reload failed: {res}")
                    elif self._correct_map_result(res):
                        parser_bin, call_graph = res
                        # Merge disassembler functions before recording in DB
                        # even when call_graph is empty — the binary may still
                        # expose internal functions needed as call targets.
                        self._merge_parser_functions_into_cached_binary(
                            parser_bin, binary, log_prefix
                        )
                        if call_graph is not None:
                            self.unresolved_callgraph[binary.path] = call_graph
                    else:
                        logging.warning(f"{log_prefix}: unexpected result during CG reload")
                else:
                    logging.warning(f"{log_prefix}: no real_path set, skipping CG reload")

                # Record in DB after the merge so internal functions discovered
                # by the disassembler are included and receive DB ids.
                self.record_binary_in_db(binary, log_prefix)
                if binary.id is not None:
                    self.node_ids[binary.id] = binary
                    self._record_custom_command(binary, log_prefix)

                progress.update(binaries_map, advance=1)
        else:
            super().map_binaries_main(threads, progress)

        if cache_file is not None:
            # Once finished stores the FS object (for fast reload)
            logging.info(f"[binary mapping]: Store cached binaries: {cache_file}")
            self.fs.write(cache_file)

    def mapper_main(
        self,
        threads: int,
        progress: Progress,
        resolution_strategy: ResolveDuplicateOption = ResolveDuplicateOption.IGNORE,
    ) -> FileSystem:
        """Main function of the mapper, return the result stored in a FileSytsem.

        :param threads: number of threads to use
        :param progress: a progress bar ready to be filled
        :param resolution_strategy: the chosen option for duplicate import resolution
        :return: The FileSystem object filled
        """  # noqa: D401
        # Step1: Load FileSystem object and enrich it if needed
        self.map_binaries_main(threads, progress)
        self.map_symlinks_main(progress)
        self.dry_run_mode = True  # do not record lib imports in numbat db
        self.map_lib_imports_main(progress, resolution_strategy)
        if self.db_interface is not None:
            self.dry_run_mode = False

        self.progress = progress
        self.exports_to_bins = self.make_export_to_binaries_map()

        # Iterate again all binaries to create call edges (all numbat_id are created)
        cg_map = progress.add_task(
            "[gold1]Call Graph mapping", total=len(list(self.fs.iter_binaries()))
        )

        unindex_symbols: set[str] = set()
        for binary in self.fs.iter_binaries():
            log_prefix = f"[cg mapping] {binary.name}"
            count_res = {True: 0, False: 0}
            if binary.path in self.unresolved_callgraph:
                for f_symb, targets in self.unresolved_callgraph[binary.path].items():
                    if not binary.function_exists(f_symb.name):
                        if targets:
                            logging.error(
                                f"function {f_symb.name} ({hex(f_symb.addr) if f_symb.addr is not None else None}) not in binary: {binary.name}"
                            )
                        continue

                    try:
                        caller = binary.get_function_by_name(f_symb.name)
                    except KeyError:
                        logging.error(
                            f"{log_prefix}: caller {f_symb.name} not found in binary {binary.name}"
                        )
                        continue

                    for target in targets:
                        try:
                            res = self._record_one_call(
                                binary,
                                caller,
                                target,
                                resolution_strategy,
                                unindex_symbols,
                                log_prefix,
                            )
                            count_res[res] += 1
                        except KeyError as e:
                            logging.error(f"{log_prefix}: can't find symbols: {e}")

            # Log amount of symbols that succeeded
            good, bad = count_res[True], count_res[False]
            logging.debug(f"{log_prefix}: Good: {good}, Bad: {bad}")

            progress.update(cg_map, advance=1)

        if len(unindex_symbols) > 0:
            logging.warning(
                f"[cg mapping]: {len(unindex_symbols)}  symbols not resolved in userland binaries "
                f"(added as unindex symbols): {', '.join(sorted(list(unindex_symbols)))}"
            )

        # return the filesystem object
        return self.fs

    def _record_custom_command(self, binary: Binary, log_prefix: str = "") -> None:
        """Add a custom command to call numbat-ui on the underlying Sourcetrail.

        :param binary: binary on which to apply the custom command
        """
        if self.dry_run_mode:
            return None
        assert self.db_interface is not None
        cmd = [NUMBAT_UI_BIN, str(binary.real_path) + ".srctrlprj"]
        if binary.id is None:
            logging.warning(f"{log_prefix}: cannot record command as binary has no id")
        else:
            self.db_interface.set_custom_command(binary.id, cmd, f"Open in {NUMBAT_UI_BIN}")

    def _record_call_ref(self, src: Symbol, dst: Symbol, log_prefix: str = "") -> bool:
        """Add call reference between two symbols in DB.

        :param src: originator of the call
        :param dst: destination of the call
        """
        if self.dry_run_mode:
            return True
        assert self.db_interface is not None
        if src.id is None or dst.id is None:
            logging.error(
                f"{log_prefix}: Cannot record call ref between '{src.name}' and "
                f"'{dst.name}', missing ids ({src.name}: {src.id}, {dst.name}: {dst.id})"
            )
            return False
        self.db_interface.record_ref_call(src.id, dst.id)
        return True

    def _record_unindexed_call(self, src: Symbol, dst: str, log_prefix: str = "") -> None:
        """Add a call to an unindexed function.

        Namely add a new function node outside of any binary and add a call reference
        to it.

        :param src: source symbol
        :param dst: destination symbol
        """
        if self.dry_run_mode:
            return None
        assert self.db_interface is not None
        # NOTE: Add a node here which have no existence at Binary/Symbol level
        tgt_id = self.db_interface.record_function(dst, is_indexed=False)
        if src.id is None or tgt_id is None:
            logging.error(
                f" {log_prefix}: Cannot record call ref between {src.name} and {dst}, "
                "both ids are not defined"
            )
            return None
        self.db_interface.record_ref_call(src.id, tgt_id)

    def make_export_to_binaries_map(self) -> dict[str, list[Binary]]:
        """Compute dict mapping: exported-funs -> binaries (exporting the function).

        Indeed multiple binaries can export the same symbol !
        """
        table = defaultdict(list)  # list there can be multiple symbols on the same address
        for binary in self.fs.iter_binaries():
            for export in binary.iter_exported_function_names():
                table[export].append(binary)
        return table

    def _record_one_call(
        self,
        binary: Binary,
        caller: Symbol,
        callee: str,
        resolver: ResolveDuplicateOption,
        unindex_symbols: set[str],
        log_prefix: str = "",
    ) -> bool:
        """Record call edge betwen caller and callee.

        The whole point of this function is to resolve the location of the target
        (callee) function. Namely finding the binary object where it lives.

        The cache enables resolving only different symbols imported from the
        same library. E.g: let's take sym1, sym2. We first resolve sym1 -> lib1.
        Then if we find out sym2 is also in lib1, then automatically consider it
        comes from there. The cache drastically reduces the number of interaction
        when using the interactive mode.

        :param binary: Binary object in which is the caller function
        :param caller: caller Symbol
        :param callee: callee function name as string
        :param resolver: resolution strategy enum

        :return: True if target function was found
        """
        # Ghidra emits template arguments in callee names (e.g. "_M_insert<bool>");
        # strip them so lookups match the base-name key in exported_functions.
        if "<" in callee:
            callee = callee[: callee.index("<")]

        # The disassembler may emit versioned symbol names (e.g. "getenv@@GLIBC_2.4").
        # All export/import keys are stored without the version suffix, so strip it.
        if "@@" in callee:
            callee = callee[: callee.index("@@")]

        if binary.function_exists(callee):
            callee_symb = binary.get_function_by_name(callee)
            binary.add_call(caller, callee_symb)
            return self._record_call_ref(caller, callee_symb, f"{log_prefix}: local call")

        if callee in IGNORE_LIST or _GHIDRA_SYNTHETIC_NAME_RE.match(callee):
            return False

        # already solved import
        if binary.imported_symbol_exists(callee, is_resolved=True):
            callee_symb = binary.get_imported_symbol(callee)
            binary.add_call(caller, callee_symb)
            return self._record_call_ref(
                caller, callee_symb, f"{log_prefix}: already solved import"
            )

        # solve import from listed imported libraries
        tmp = self.resolve_symbol_import(binary, callee, resolver, log_prefix)
        if tmp is not None:
            target_bin, target_symb = tmp
            if not binary.imported_library_exists(target_bin.name):
                binary.add_imported_library(target_bin)
            binary.add_imported_symbol(target_symb)
            binary.add_call(caller, target_symb)
            return self._record_call_ref(
                caller, target_symb, f"{log_prefix}: import in listed imported lib"
            )

        # Get binaries exporting this symbol
        served_by: list[Binary] = self.exports_to_bins[callee]

        # if multiple binaries are exposing the symbol try discriminating the symbol
        if len(served_by) > 1:
            if resolver == ResolveDuplicateOption.INTERACTIVE and self.progress is not None:
                with hide_progress(self.progress):
                    choice = self._select_fs_component(resolver, served_by, log_prefix, callee)
            else:
                choice = self._select_fs_component(resolver, served_by, log_prefix, callee)
            if choice:
                # if a choice has been done
                served_by = [choice]  # registerded just below
            else:
                logging.warning(
                    f"{log_prefix}: several matches for edge {caller} -> {callee}:"
                    f"{[x.name for x in served_by]}"
                )
                return False
        if len(served_by) == 1:
            binary.add_imported_library(served_by[0])
            callee_symb = served_by[0].get_exported_symbol(callee)
            binary.add_imported_symbol(callee_symb)
            binary.add_call(caller, callee_symb)
            return self._record_call_ref(caller, callee_symb, log_prefix)
        else:  # still not resolved
            self._record_unindexed_call(caller, callee, log_prefix)
            if binary.path.suffix != ".ko":
                unindex_symbols.add(callee)
                logging.warning(f"{log_prefix}: no match found for edge {caller.name} -> {callee}")
            else:
                logging.debug(f"{log_prefix}: no match found for edge {caller.name} -> {callee}")
            return False
