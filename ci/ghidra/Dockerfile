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

FROM openjdk:21-jdk-slim
SHELL ["/bin/bash", "-c"]

# ======================== Ghidra Installation =================================

ARG GHIDRA_VERSION=11.1.2
ARG GHIDRA_RELEASE_DATE=20240709
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    ca-certificates \
    libfreetype6 \
    libmagic1 \
    libpython3-dev \
    python3-minimal \
    python3-pip \
    python3-venv \
    python-is-python3 \
    unzip \
    wget \
    &&  rm -rf /var/lib/apt/lists/*

RUN wget $GHIDRA_URL -O ghidra.zip && unzip ghidra.zip -d /opt/ && rm ghidra.zip

ENV PATH=${GHIDRA_INSTALL_DIR}:${PATH}

# ======================== Plugin Installation ==============================

ARG BINEXPORT_URL=https://github.com/google/binexport/archive/refs/heads/main.zip
ARG GRADLE_VERSION=8.14.3
ARG GRADLE_URL=https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip
ARG GHIDRA_PLUGIN_DIR=/root/.config/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC/Extensions

RUN wget ${GRADLE_URL} -O gradle.zip  \
    && unzip gradle.zip -d gradle \
    && wget ${BINEXPORT_URL} -O binexport.zip \
    && mkdir -p ${GHIDRA_PLUGIN_DIR} \
    && unzip binexport.zip  binexport-main/java/* -d binexport \
    && (cd binexport/binexport-main/java/ && /gradle/gradle-${GRADLE_VERSION}/bin/gradle buildExtension -PGHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR} && unzip dist/ghidra_${GHIDRA_VERSION}_PUBLIC_$( date +%Y%m%d)_BinExport.zip -d ${GHIDRA_PLUGIN_DIR}) \
    && rm -rf gradle.zip gradle binexport.zip binexport \
    && apt-get purge --yes wget unzip  && apt --yes autoremove

CMD ["/bin/bash"]