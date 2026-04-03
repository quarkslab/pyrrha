import pytest

from pyrrha_mapper.types import Backend


def pytest_addoption(parser):
    parser.addoption(
        "--backend",
        action="store",
        help="backend",
        choices={x.name.lower() for x in Backend},
    )