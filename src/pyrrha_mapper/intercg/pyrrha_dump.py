import json
from pathlib import Path


class PyrrhaDump(object):
    def __init__(self, file: Path):
        self.data = json.load(file.open())
        self.sym_by_name = {x['name']: x for x in self.data['symbols'].values()}
        self.bin_by_path = {x['path']: x for x in self.data['binaries'].values()}
        self.symlinks_by_path= {x['path']: x for x in self.data['symlinks'].values()}

    def get_path(self, id: str|int) -> str:
        return self.data['binaries'][str(id)]['path']

    def get_id(self, path: str) -> int | None:
        for id, bin_entry in self.data['binaries'].items():
            if bin_entry['path'] == path:
                return id
        return None

    def to_symbol_str(self, symbol_list: list[int]) -> set[str]:
        return set([self.data['symbols'][str(x)]['name'] for x in symbol_list])

    def to_binary_str(self, binary_list: list[int]) -> set[str]:
        return set([self.data['binaries'][str(x)]['name'] for x in binary_list])

    def get_exported_symbols(self, id: str | int) -> list[str]:
        entry = self.data['binaries'][str(id)]
        return [self.data['symbols'][str(x)]['name'] for x in entry['export_ids']]

    def get_dependencies(self, pyr_id: str | int) -> dict[int, dict]:
        entry = self.data['binaries'][str(pyr_id)]
        return {int(x): self.data['binaries'][str(x)] for x in entry['imports']['lib']['ids']}

    def get_imported_symbols(self, pyr_id: str | int) -> dict[int, dict]:
        entry = self.data['binaries'][str(pyr_id)]
        return {int(x): self.data['symbols'][str(x)] for x in entry['imports']['symbols']['ids']}
