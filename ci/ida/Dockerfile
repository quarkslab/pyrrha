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

FROM docker.io/library/debian:testing-slim
SHELL ["/bin/bash", "-c"]

# ============= How to generate the required data ===========================
# paths can be changed from commandline if needed
# idapro.hexlic: license file, downloaded from your account on hex-rays website
# ida-pro_91.run: executable file, downloaded from your account on hex-rays website
# ida.reg: history file, to be generated manually. Keep in memory that the licence has alredy been accepted.
#      1. Build this docker with an empty ida.reg and launch it.
#      2. Launch idat and accept the license.
#      3. In another terminal, get the id of the current ida docker with `docker ps`
#      4. Run `docker cp ID:/root/.idapro/ida.reg ./` where ID is the id get at the 
#         previous step, you know have a correct ida.reg.
#      5. Rebuild your image with the correct ida.reg
# ===========================================================================

# ======================== IDA Installation =================================

ARG IDA_VERSION=91
ARG IDA_INSTALLER=ida-pro_${IDA_VERSION}.run
ENV IDA_INSTALL_DIR=/opt/ida_${IDA_VERSION}

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    ca-certificates \
    ccache \
    cmake \
    g++ \
    gcc \
    git \
    libpython3-dev \
    libqt5gui5 \
    libfontconfig1 \
    libmagic1 \
    libsecret-1-0 \
    make \
    ninja-build \
    python3-minimal \
    python3-pip \
    python3-venv \
    python-is-python3 \
    unzip \
    xcb-proto \
    wget \
    zlib1g-dev \
    && mkdir -p $IDA_INSTALL_DIR ~/.local/share/applications/

RUN --mount=type=bind,src=${IDA_INSTALLER},target=${IDA_INSTALLER} DEBIAN_FRONTEND=noninteractive apt-get install --yes --reinstall libxcb-xinerama0 && \
    ./${IDA_INSTALLER} --mode unattended --prefix ${IDA_INSTALL_DIR}

ENV PATH=${IDA_INSTALL_DIR}:${PATH}

# ======================== Plugin Installation ==============================

ARG QUOKKA_VERSION=v0.6.1
ARG QUOKKA_URL=https://github.com/quarkslab/quokka/releases/download/${QUOKKA_VERSION}/${IDA_VERSION}-quokka_plugin0064.so
ARG BINEXPORT_URL=https://github.com/google/binexport/releases/download/v12-20240417-ghidra_11.0.3/BinExport-Linux.zip
RUN if [[ ${IDA_VERSION} -eq 84 ]]; then \
    wget ${QUOKKA_URL} -O ${IDA_INSTALL_DIR}/plugins/quokka64.so \
    && wget ${BINEXPORT_URL} -O binexport.zip \
    && unzip -j binexport.zip ida/binexport12_ida.so ida/binexport12_ida64.so -d ${IDA_INSTALL_DIR}/plugins/ \
    && rm -f binexport.zip ; \
    else wget ${QUOKKA_URL} -O ${IDA_INSTALL_DIR}/plugins/quokka.so ; fi \
    && apt-get purge --yes wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home -u 1000 -m user && chown -R user:user $IDA_INSTALL_DIR
USER user
RUN $IDA_INSTALL_DIR/idapyswitch -a
WORKDIR /home/user
