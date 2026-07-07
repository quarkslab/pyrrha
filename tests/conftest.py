# -*- coding: utf-8 -*-

#  Copyright 2023-2026 Quarkslab
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
"""Pytest configuration and shared fixtures."""

import logging
import os
import shutil
from pathlib import Path

import pytest

from pyrrha_mapper.types import Backend


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register custom CLI options."""
    parser.addoption(
        "--backend",
        action="store",
        help="backend",
        choices={x.name.lower() for x in [Backend.IDA, Backend.GHIDRA]},
    )


@pytest.fixture(autouse=True)
def _collect_export_artifacts(request: pytest.FixtureRequest) -> None:
    """Copy artifacts produced by export_res to PYTEST_ARTIFACTS_DIR when it is set."""
    artifacts_dir = os.environ.get("PYTEST_ARTIFACTS_DIR")
    if not artifacts_dir:
        return
    # Only act when the test used the export_res fixture.
    if "export_res" not in request.fixturenames:
        return

    def _copy() -> None:
        try:
            export_res = request.getfixturevalue("export_res")
        except pytest.FixtureLookupError:
            return
        dest = Path(artifacts_dir)
        dest.mkdir(parents=True, exist_ok=True)
        for path in [
            export_res.export_path,
            export_res.db_path,
            export_res.project_path,
        ]:
            if not path.exists():
                continue
            target = dest / path.name
            # Artifact collection is a best-effort convenience: it must never
            # fail a test. The destination may already exist and be read-only
            # (e.g. a job that downloads another job's artifacts into the same
            # directory restores them read-only), so drop it first and ignore
            # any copy error.
            try:
                if target.exists():
                    target.unlink()
                shutil.copy2(path, target)
            except OSError as error:
                logging.warning(f"could not collect artifact {path.name}: {error}")

    request.addfinalizer(_copy)
