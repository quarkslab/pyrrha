# -*- coding: utf-8 -*-

#  Copyright 2023-2025 Quarkslab
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

# -----------------------------------------------------------------------------
# Pyrrha image
#
# Layered on top of an image which contained one of the supported disassembler.
# The image should provide:
#   * the disassembler already installed and on PATH (or correct env variable set)
#   * a non-root "user" (uid 1000)
#   * a Python >= 3.11 venv already on PATH
#
# The base image tag is parameterised so callers can reuse a pre-built image or
# have it built on-demand by scripts/build-docker.sh.
#
# Manual usage:
#   docker build -t pyrrha-ghidra:latest ci/ghidra
#   docker build -t pyrrha-ida:latest \
#       --build-arg DISASS_IMAGE=ida --build-arg DISASS_IMAGE_VERSION=latest .
# -----------------------------------------------------------------------------

ARG GHIDRA_IMAGE=pyrrha-ghidra:latest

ARG DISASS_IMAGE=ghidra
ARG DISASS_IMAGE_VERSION=latest

FROM ${DISASS_IMAGE}:${DISASS_IMAGE_VERSION}
SHELL ["/bin/bash", "-c"]

ENV DISASS_IMAGE_USER=user
ENV PYRRHA_INSTALL_DIR=/tmp/pyrrha_install
ENV PYRRHA_WORKING_DIR=/tmp/pyrrha

USER ${DISASS_IMAGE_USER}
WORKDIR ${PYRRHA_INSTALL_DIR}

RUN python3 -m pip install --no-cache-dir -U pip

COPY --chown=${DISASS_IMAGE_USER}:${DISASS_IMAGE_USER} src src/
COPY --chown=${DISASS_IMAGE_USER}:${DISASS_IMAGE_USER} pyproject.toml ./
COPY --chown=${DISASS_IMAGE_USER}:${DISASS_IMAGE_USER} README.md ./


# Overwrite the PyPI install from the base image with the local working copy.
# --force-reinstall guarantees we replace the base layer's version even when
# the local pyproject.toml reports an identical version number.
RUN pip install --no-cache-dir --force-reinstall . && \
    rm -rf ${PYRRHA_INSTALL_DIR}

WORKDIR ${PYRRHA_WORKING_DIR}

CMD ["pyrrha"]
