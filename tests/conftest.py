import pytest
from qbinary.types import ExportFormat, Disassembler

def pytest_addoption(parser):
    parser.addoption(
        "--disassembler",
        action="store",
        help="disassembler",
        choices={x.name.lower() for x in Disassembler},
    )
    parser.addoption(
        "--exporter",
        action="store",
        help="exporter",
        choices={x.name.lower() for x in ExportFormat},
    )