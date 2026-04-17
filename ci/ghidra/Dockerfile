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


# ======================== Ghidra Download and Extraction ==============================
# Use a dedicated stage so that wget, unzip, and the zip archive itself are
# never committed to the final image layer.
FROM debian:bookworm-slim AS ghidra-download

ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_RELEASE_DATE=20260303
ARG GHIDRA_SHA256=c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip

RUN apt-get update && \
    apt-get install --yes --no-install-recommends \
    ca-certificates \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Download, verify checksum, extract, then discard the archive immediately.
# Also strip files not needed at runtime to reduce COPY --from size.
RUN wget --no-verbose "${GHIDRA_URL}" -O /tmp/ghidra.zip && \
    echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum --check --strict && \
    unzip -q /tmp/ghidra.zip -d /opt/ && \
    rm /tmp/ghidra.zip && \
    find /opt/ghidra_${GHIDRA_VERSION}_PUBLIC -name "*.bat" -delete && \
    rm -rf \
    /opt/ghidra_${GHIDRA_VERSION}_PUBLIC/docs \
    /opt/ghidra_${GHIDRA_VERSION}_PUBLIC/Extensions/Eclipse \
    /opt/ghidra_${GHIDRA_VERSION}_PUBLIC/licenses

# ======================== Ghidra Installation and Runtime Image =======================
# eclipse-temurin:21-jdk-jammy is the current maintained replacement for the
# deprecated openjdk:21-jdk-slim. The full JDK is required as Ghidra's
# launcher validates the Java installation and rejects JRE-only setups.
FROM eclipse-temurin:21-jdk-jammy

ARG GHIDRA_VERSION=12.0.4

# Exported so that pyghidra and other tools spawned inside the container can
# locate the Ghidra installation without extra configuration.
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_${GHIDRA_VERSION}_PUBLIC
ENV PATH=${GHIDRA_INSTALL_DIR}:${PATH}

# Copy only the extracted Ghidra tree from the download stage — no wget/unzip
# tooling or archive bytes are present in this layer.
COPY --from=ghidra-download /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_INSTALL_DIR}

# Install the minimal runtime dependencies for Ghidra headless + pyghidra and
# for building/installing the pyrrha-mapper Python package.
# Python 3.11 is installed via the deadsnakes PPA as Ubuntu 22.04 (Jammy)
# ships 3.10 by default.
# All apt artefacts are removed in the same RUN layer to keep layer size down.
RUN apt-get update && \
    apt-get install --yes --no-install-recommends \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install --yes --no-install-recommends \
    libfreetype6 \
    libmagic1 \
    python3.11 \
    python3.11-venv \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Make python3.11 the default python3 and python.
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1

# User creation
RUN useradd --create-home -u 1000 -m user && \
    chown -R user:user "${GHIDRA_INSTALL_DIR}"

USER user
WORKDIR /home/user

# Python virtual environment — activated automatically for both interactive
# shells (.bashrc) and non-interactive processes (ENV PATH).
ENV VIRTUAL_ENV=/home/user/.venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN python3.11 -m venv "${VIRTUAL_ENV}" && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir pyrrha-mapper && \
    echo "source ${VIRTUAL_ENV}/bin/activate" >> /home/user/.bashrc

CMD ["/bin/bash"]