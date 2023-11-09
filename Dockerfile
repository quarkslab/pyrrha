# -*- coding: utf-8 -*-

#  Copyright 2023 Quarkslab
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

FROM docker.io/library/python:3.11-slim
SHELL ["/bin/bash", "-c"]

ENV PYRRHA_INSTALL_DIR=/tmp/pyrrha_install
ENV PYRRHA_WORKING_DIR=/tmp/pyrrha

RUN mkdir -p $PYRRHA_INSTALL_DIR

WORKDIR ${PYRRHA_INSTALL_DIR}

RUN python3 -m pip install --no-cache-dir -U pip

COPY src src/
COPY setup.py ./
COPY pyproject.toml ./
COPY README.md ./

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake build-essential && \
    python3 -m pip install --no-cache-dir . && \
    apt-get autoremove -y --purge cmake build-essential && \
    rm -rf $PYRRHA_INSTALL_DIR /var/lib/apt/lists/*

WORKDIR ${PYRRHA_WORKING_DIR}

ENTRYPOINT ["pyrrha"]
