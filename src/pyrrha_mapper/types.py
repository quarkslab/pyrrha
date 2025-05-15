"""Types shared in multiple mappers"""
from enum import Enum, auto


class Disassembler(Enum):
    """
    Enum to represent a SRE (Software Reverse Engineering tool)
    aka a disassembler.
    """

    AUTO = auto()         # doc: Disassembler shall selected automatically
    IDA = auto()          # doc: IDA Pro disassembler
    GHIDRA = auto()       # doc: GHIDRA disassembler
    BINARY_NINJA = auto() # doc: Binary Ninja disassembler


class Exporters(Enum):
    """
    Enum to represent export file formats used in some
    of the mappers.
    """
    AUTO = auto()      # doc: The exporter shall be automatically selected
    BINEXPORT = auto() # doc: Use Binexport as exporter
    QUOKKA = auto()    # doc: Use Quokka as exporter


class ResolveDuplicateOption(Enum):
    """
    Enum to represent the strategy of resolution when the mapper cannot solve it.
    """
    IGNORE = 1       # doc: The mapper will let the conflict as unresolved.
    ARBITRARY = 2    # doc: The mapper will choose a default one.
    INTERACTIVE = 3  # doc: The user can interactively solve the conflict.
