#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import re


class PyrrhaDump():
    def __init__(self, file):
        self.data = json.loads(Path(file).read_text())
        self.sym_by_name = {x['name']: x for x in self.data['symbols']}
        self.sym_by_id = {x['id']: x for x in self.data['symbols']}
        self.bin_by_path = {x['path']: x for x in self.data['binaries']}
        self.bin_by_id = {x['id']: x for x in self.data['binaries']}

    def to_symbol_str(self, symbol_list: list[int]) -> set[str]:
        return set([self.sym_by_id[x]['name'] for x in symbol_list])

    def to_binary_str(self, binary_list: list[int]) -> set[str]:
        return set([self.bin_by_id[x]['name'] for x in binary_list])


def main(json1, json2):
    pyrrha1 = PyrrhaDump(json1)
    pyrrha2 = PyrrhaDump(json2)

    set1o = set(s for s in pyrrha1.bin_by_path)  # sets without kernel mangling
    set2o = set(s for s in pyrrha2.bin_by_path)
    set1 = set(re.sub("\/lib\/modules\/\d+\.\d+\.\d+", "/[KERNEL_VERSION]", s) for s in pyrrha1.bin_by_path)
    set2 = set(re.sub("\/lib\/modules\/\d+\.\d+\.\d+", "/[KERNEL_VERSION]", s) for s in pyrrha2.bin_by_path)

    print(f"Binaries no longer in {json2}:")
    for b in set1 - set2:
        print(f"  - {b}")

    print(f"\nBinaries added in {json2}:")
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
    if len(sys.argv) != 3:
        print("Usage: ./04c-firmware-changes-pyrrha json_dump1 json_dump2")

    # PYRRHA_DUMP1 = "pyrrha_results/v1.0.7.78.json"
    # PYRRHA_DUMP2 = "pyrrha_results/v1.0.9.90.3.json"
    main(sys.argv[1], sys.argv[2])