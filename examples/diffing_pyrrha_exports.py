#!/usr/bin/env python3
"""This script diff two Pyrrha result JSON exports.
It removes the kernel mangling"""

import argparse
import json
from pathlib import Path
import re


def existing_file(raw_path: str) -> Path | None:
    """
    This function check if a given path correspond to an existing file, and if so
    creates the corresponding pathlib.Path object.
    :param raw_path: the given path (as a string)
    :return: the corresponding pathlib.Path object
    """
    if not Path(raw_path).exists():
        raise argparse.ArgumentTypeError('"{}" does not exist'.format(raw_path))
    elif not Path(raw_path).is_file():
        raise argparse.ArgumentTypeError('"{}" is not a file'.format(raw_path))
    return Path(raw_path)


class PyrrhaDump():
    def __init__(self, file: Path):
        self.data = json.load(file.open())
        self.sym_by_name = {x['name']: x for x in self.data['symbols'].values()}
        self.bin_by_path = {x['path']: x for x in self.data['binaries'].values()}

    def to_symbol_str(self, symbol_list: list[int]) -> set[str]:
        return set([self.data['symbols'][str(x)]['name'] for x in symbol_list])

    def to_binary_str(self, binary_list: list[int]) -> set[str]:
        return set([self.data['binaries'][str(x)]['name'] for x in binary_list])


def main():
    # parse command line to retrieve OTA path
    parser = argparse.ArgumentParser()
    parser.add_argument('json1', type=existing_file, help='Path to first JSON.')
    parser.add_argument('json2', type=existing_file, help='Path to second JSON.')
    args = parser.parse_args()

    pyrrha1 = PyrrhaDump(args.json1)
    pyrrha2 = PyrrhaDump(args.json2)

    set1o = set(s for s in pyrrha1.bin_by_path)  # sets without kernel mangling
    set2o = set(s for s in pyrrha2.bin_by_path)
    set1 = set(re.sub("\/lib\/modules\/\d+\.\d+\.\d+", "/[KERNEL_VERSION]", s) for s in pyrrha1.bin_by_path)
    set2 = set(re.sub("\/lib\/modules\/\d+\.\d+\.\d+", "/[KERNEL_VERSION]", s) for s in pyrrha2.bin_by_path)


    print(f"Binaries no longer in {args.json2}:")
    for b in set1 - set2:
        print(f"  - {b}")

    print(f"\nBinaries added in {args.json2}:")
    for b in set2 - set1:
        print(f"  - {b}")

    print("\nCommon binaries that have changed:")
    count = 0
    for b1, b2 in ((pyrrha1.bin_by_path[x], pyrrha2.bin_by_path[x]) for x in set1o.intersection(set2o)):
        libs1 = pyrrha1.to_binary_str(b1['imports']['lib']['ids'])
        libs2 = pyrrha2.to_binary_str(b2['imports']['lib']['ids'])
        is_different = False
        if libs1 != libs2:
            count += 1
            print(f"{b1['name']} have changed:")
            is_different = True
            if r := libs1 - libs2:
                print(f"  - lib removed: {r}")
            if r := libs2 - libs1:
                print(f"  - lib added: {r}")

        syms1 = pyrrha1.to_symbol_str(b1['imports']['symbols']['ids'])
        syms2 = pyrrha2.to_symbol_str(b2['imports']['symbols']['ids'])
        if syms1 != syms2:
            if not is_different:
                count += 1
                print(f"{b1['name']} have changed:")
            if r := syms1 - syms2:
                print(f"  - symbols removed: {r}")
            if r := syms2 - syms1:
                print(f"  - symbols added: {r}")
    print(f"Total having changed: {count}")


if __name__ == "__main__":
    main()
