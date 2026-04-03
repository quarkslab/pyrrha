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

# ============= How to generate the required data ===========================
# All sensitive files are passed exclusively via --mount=type=secret so they
# never appear in any image layer or in `docker history`.
#
# Required files (place them next to this Dockerfile):
#   idapro.hexlic : license file, downloaded from your account on hex-rays website
#   ida-pro_91.run: executable installer, downloaded from your account on hex-rays website
#
# Build command:
#   docker build \
#     --secret id=ida_installer,src=ida-pro_91.run \
#     -t pyrrha-ida .
#
# ida.reg is generated automatically during the build (see stage 1).
#
# Run command (licence is mounted at runtime, never stored in the image):
#   docker run --rm \
#     --mount type=secret,id=ida_license,src=idapro.hexlic \
#     pyrrha-ida
#
# IDA locates the licence via the HEXRAYS_LICENSE env var which is set to the
# secret path below.
# ===========================================================================

# ======================== IDA Installation =================================
# Contains build-only packages and the installer; none of this reaches the
# final image.
FROM docker.io/library/debian:testing-slim AS ida-install

ARG IDA_VERSION=91
ARG IDA_INSTALL_DIR=/opt/ida_${IDA_VERSION}

# Build-time dependencies:
#   - libxcb-xinerama0  : required by the .run installer's Qt bootstrap
#   - xvfb              : provides a virtual framebuffer so that idat can run
#                         headlessly long enough to accept the licence and write
#                         ida.reg on first launch
#   - remaining libs    : runtime deps that are also needed at install time
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    libfontconfig1 \
    libmagic1 \
    libqt5gui5 \
    libsecret-1-0 \
    libxcb-xinerama0 \
    python3-minimal \
    python-is-python3 \
    xvfb \
    && mkdir -p "${IDA_INSTALL_DIR}" ~/.local/share/applications/ \
    && rm -rf /var/lib/apt/lists/*

# Run the installer in a secret-mount RUN so the .run binary is never
# committed to any layer. The licence is intentionally NOT copied here;
# it will be mounted at runtime only (see run command above).
RUN --mount=type=secret,id=ida_installer,target=/tmp/ida_installer.run \
    chmod +x /tmp/ida_installer.run && \
    DEBIAN_FRONTEND=noninteractive /tmp/ida_installer.run \
    --mode unattended \
    --prefix "${IDA_INSTALL_DIR}"

# Generate ida.reg by launching idat once inside a virtual framebuffer.
# The -A flag auto-accepts the EULA; idat exits after startup with no project.
# ida.reg is written to root's home by default.
RUN Xvfb :99 -screen 0 1024x768x24 & \
    sleep 2 && \
    DISPLAY=:99 "${IDA_INSTALL_DIR}/idat" -A && \
    sleep 5 && \
    kill %1 || true

# ======================== IDA Runtime image =================================
# Only the IDA tree, the licence, ida.reg, and the runtime shared libraries are
# present here. No installer, no xvfb, no build tooling.
FROM docker.io/library/debian:testing-slim

ARG IDA_VERSION=91

# Exported so that qbinary/idascript and other tools spawned inside the
# container can locate the IDA installation without extra configuration.
ENV IDA_INSTALL_DIR=/opt/ida_${IDA_VERSION}
ENV PATH=${IDA_INSTALL_DIR}:${PATH}
# IDA looks for the licence at the path provided by this variable.
# At runtime, mount the licence as a secret at that exact path:
#   docker run --mount type=secret,id=ida_license,src=idapro.hexlic,...
ENV HEXRAYS_LICENSE=/run/secrets/ida_license
# IDADIR is required by ida_domain to locate the IDA installation at runtime.
ENV IDADIR=${IDA_INSTALL_DIR}

# Runtime-only shared libraries required by IDA and its Qt layer.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    libfontconfig1 \
    libmagic1 \
    libqt5gui5 \
    libsecret-1-0 \
    python3-minimal \
    python-is-python3 \
    && rm -rf /var/lib/apt/lists/*

# Copy only the installed IDA tree from the build stage.
COPY --from=ida-install ${IDA_INSTALL_DIR} ${IDA_INSTALL_DIR}

# User creation
RUN useradd --create-home -u 1000 -m user && \
    chown -R user:user "${IDA_INSTALL_DIR}"

USER user
WORKDIR /home/user

# Copy ida.reg (generated in stage 1) into the user's IDA config directory.
COPY --from=ida-install /root/.idapro/ida.reg /home/user/.idapro/ida.reg

# virtualenv (automatically launch at runtime)
ENV VIRTUAL_ENV=/home/user/.venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
RUN python -m venv "${VIRTUAL_ENV}" && \
    echo "source ${VIRTUAL_ENV}/bin/activate" >> /home/user/.bashrc

RUN "${IDA_INSTALL_DIR}/idapyswitch" -a

CMD ["/bin/bash"]
