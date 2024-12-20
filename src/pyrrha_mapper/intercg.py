import logging
from dataclasses import dataclass, field
from pathlib import Path

from numbat import SourcetrailDB

from pyrrha_mapper.filesystem import Binary

@dataclass
class Function:
    """Represent a function and its various components/metadata"""
    name: str
    address: int
    binary: Binary
    id: int = None
    exported: bool = False
    calls: list[int] = field(default_factory=list)  # list of addresses


class InterCGBinary(Binary):
    functions: dict[int, Function] = field(default_factory=dict)  # dict(addr, function)

    @staticmethod
    def is_supported(p: Path) -> bool:
        """
        Check if the given path points on a file (NOT via a symlink) which is
        of a format handled by this parser.
        :param p: the path of the file to analyzed
        :return: True is the path point on a file
        """
        return p.is_file() and not p.is_symlink()

    def load(self):
        # list imported libs
        # list imported symbols
        # list exported symbols
        # list internal functions and internal calls
        pass

    def record_in_db(self, db: SourcetrailDB) -> None:
        """record the Binary and its components in the DB"""
        self.id = db.record_class(self.name, prefix=f"{self.fw_path.parent}/", delimiter=":")
        # record functions
        for f in self.functions.values():
            f.id = db.record_symbol_node(f.name, parent_id=self.id)
            if f.exported:
                db.record_public_access(f.id)
                self.exported_function_ids[f.name] = f.id
            else:
                db.record_private_access(f.id)
        # record exported symbols
        for name in self.exported_symbol_ids.keys():
            node_id = db.record_symbol_node(name, parent_id=self.id)
            db.record_public_access(node_id)
            self.exported_symbol_ids[name] = node_id
        # record internal calls
        for f in self.functions.values():
            for addr in f.calls:
                if addr in self.functions:
                    db.record_ref_call(self.id, self.functions[addr].id)
                else:
                    logging.warning("address {addr} does not correspond to a function of the binary {self.name}")
