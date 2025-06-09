#!/usr/bin/env python3
"""Diff two Pyrrha result JSON exports.It removes the kernel mangling."""

import argparse
from pathlib import Path

from pyrrha_mapper import FileSystem


def existing_file(raw_path: str) -> Path | None:
    """Check if a path correspond to an existing file and transform it into a pathlib.Path object.

    :param raw_path: the given path (as a string)
    :return: the corresponding pathlib.Path object
    """
    if not Path(raw_path).exists():
        raise argparse.ArgumentTypeError('"{}" does not exist'.format(raw_path))
    elif not Path(raw_path).is_file():
        raise argparse.ArgumentTypeError('"{}" is not a file'.format(raw_path))
    return Path(raw_path)


def main():
    """Diff two exports of `fs` result."""
    parser = argparse.ArgumentParser()
    parser.add_argument("json1", type=existing_file, help="Path to old filesystem JSON.")
    parser.add_argument("json2", type=existing_file, help="Path to new filesystem JSON.")
    args = parser.parse_args()

    old_fs = FileSystem.from_json_export(args.json1)
    new_fs = FileSystem.from_json_export(args.json2)

    # Compute and display changes of binaries
    old_bins = {b.path for b in old_fs.iter_binaries()}
    new_bins = {b.path for b in new_fs.iter_binaries()}
    added_bin = new_bins - old_bins
    removed_bin = old_bins - new_bins
    for type, bin_set in [("no longer", removed_bin), ("added", added_bin)]:
        print(f"\nBinaries {type} in {args.json2}:")
        for b in bin_set:
            print(f"\t- {b}")

    print("\nCommon binaries that have changed:")
    count = 0
    for b1, b2 in (
        (old_fs.get_binary_by_path(path), new_fs.get_binary_by_path(path))
        for path in old_bins.intersection(new_bins)
    ):
        is_different = False
        old_libs, new_libs = set(b1.imported_library_names), set(b2.imported_library_names)
        if old_libs != new_libs:
            count += 1
            print(f"{b1.name} have changed:")
            is_different = True
            for type, bin_set in [("removed", old_libs - new_libs), ("added", new_libs - old_libs)]:
                for lib in bin_set:
                    print(f"\t- lib {type}: {lib}")

        old_symbs, new_symbs = set(b1.imported_symbol_names), set(b2.imported_symbol_names)
        if old_symbs != new_symbs:
            if not is_different:
                count += 1
                print(f"{b1.name} have changed:")
            is_different = True
            for type, bin_set in [
                ("removed", old_symbs - new_symbs),
                ("added", new_symbs - old_symbs),
            ]:
                for lib in bin_set:
                    print(f"\t- imported symbol {type}: {lib}")
    print(f"Total having changed: {count}")


if __name__ == "__main__":
    main()
