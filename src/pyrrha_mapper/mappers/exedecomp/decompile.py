#!/usr/bin/env python3
import json
from pathlib import Path
import sys

try:
    import ida_auto
    import idautils
    import ida_nalt
    import ida_pro
    import ida_hexrays
    INSIDE_IDA = True
except ImportError:
    INSIDE_IDA = False

    from idascript import MultiIDA, iter_binary_files, IDA


def main_ida():
    ida_auto.auto_wait()

    input_file = ida_nalt.get_input_file_path()
    output_file = input_file+".decompiled"

    funs = {}

    for fun_ea in idautils.Functions():
        decomp = ida_hexrays.decompile(fun_ea)
        if decomp is not None:
            funs[fun_ea] = str(decomp)

    with open(output_file, "w") as f:
        f.write(json.dumps(funs))

    ida_pro.qexit(0)


def file_iterator(path):
    for file in iter_binary_files(path):
        ida_i64 = Path(str(file)+".i64")
        if ida_i64.exists():
            yield file


def main_main():
    """
    Main function called when launched normally
    """
    if len(sys.argv) != 2:
        print("Usage: decompile_program.py dir/")
        sys.exit(1)

    root = sys.argv[1]

    # For each file identified launch many IDA in parrallel this very same script
    for (file, retcode) in MultiIDA.map(file_iterator(root), __file__, [], 6):
        print(f"Processed {file} [{retcode}]")


if __name__ == "__main__":
    if INSIDE_IDA:
        main_ida()
    else:
        main_main()
