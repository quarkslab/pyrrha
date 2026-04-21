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
#     --build-arg IDA_VERSION=91 \
#     --build-arg IDA_INSTALLER=ida-pro_91.run \
#     -t pyrrha-ida .
#
# ida.reg is injected by Dockerfile.final after interactive EULA acceptance.
# See build_ida.sh for the full two-phase build procedure.
#
# Run command (licence is mounted at runtime, never stored in the image):
#   docker run --rm \
#     --mount type=bind,dsr=/home/user/.idapro/ida_license.hexlic,src=idapro.hexlic,ro \
#     pyrrha-ida
#
# ===========================================================================

# ======================== IDA Installation =================================
# Contains build-only packages and the installer; none of this reaches the
# final image.
FROM docker.io/library/debian:testing-slim AS ida-install

ARG IDA_VERSION=91
ARG IDA_INSTALL_DIR=/opt/ida_${IDA_VERSION}

# Path to the installer .run file on the build host, passed via --build-arg.
# It is bind-mounted into the build container at a fixed target path so that
# the ARG value (which Docker cannot expand inside --mount options) is only
# used inside the shell command where substitution works normally.
ARG IDA_INSTALLER=ida-pro_${IDA_VERSION}.run

# Build-time dependencies:
#   - libxcb-xinerama0  : required by the .run installer's Qt bootstrap
#   - libopengl0        : required by IDA's Qt layer for rendering
#   - remaining libs    : runtime deps also needed at install time
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    libfontconfig1 \
    libmagic1 \
    libopengl0 \
    libqt5gui5 \
    libsecret-1-0 \
    libxcb-xinerama0 \
    python3-minimal \
    python-is-python3 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
    && mkdir -p "${IDA_INSTALL_DIR}" ~/.local/share/applications/

# The installer is bind-mounted from the build context so the large .run
# binary is never written to any layer. Docker cannot expand ARGs inside
# --mount options, so src=. mounts the whole context and the ARG is used
# only inside the shell command where substitution works normally.
ARG IDA_INSTALLER
RUN --mount=type=bind,src=.,target=/build/context \
    cp "/build/context/${IDA_INSTALLER}" /tmp/ida_installer.run && \
    chmod +x /tmp/ida_installer.run && \
    DEBIAN_FRONTEND=noninteractive /tmp/ida_installer.run \
    --mode unattended \
    --prefix "${IDA_INSTALL_DIR}" && \
    rm /tmp/ida_installer.run && \
    # Strip unneeded files from the IDA tree to reduce COPY --from size:
    #   - documentation
    #   - desktop integration files
    #   - uninstaller
    rm -rf \
    "${IDA_INSTALL_DIR}/README_python3.txt" \
    "${IDA_INSTALL_DIR}/Uninstall IDA"* \
    "${IDA_INSTALL_DIR}/uninstall"* \
    "${IDA_INSTALL_DIR}/appico.png" \
    "${IDA_INSTALL_DIR}/hvui.png"

# ======================== IDA Runtime image =================================
# Only the IDA tree and the runtime shared libraries are present here.
# No installer, no build tooling.
# ida.reg is NOT present at this stage — it is injected by Dockerfile.final
# after the user has accepted the EULA interactively (see build_ida.sh).
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
# apt-get clean and list removal are in the same layer to avoid bloat.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    libfontconfig1 \
    libmagic1 \
    libopengl0 \
    libpython3.13 \
    libqt5gui5 \
    libsecret-1-0 \
    libxcb-cursor0 \
    python3-minimal \
    python3-venv \
    python-is-python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Copy only the installed IDA tree from the build stage.
COPY --from=ida-install ${IDA_INSTALL_DIR} ${IDA_INSTALL_DIR}

# ── User creation ─────────────────────────────────────────────────────────────
RUN useradd --create-home -u 1000 -m user && \
    chown -R user:user "${IDA_INSTALL_DIR}"

USER user
WORKDIR /home/user

# virtualenv (automatically activated at runtime for both interactive and
# non-interactive sessions via ENV PATH and .bashrc respectively)
ENV VIRTUAL_ENV=/home/user/.venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
RUN python -m venv "${VIRTUAL_ENV}" && \
    echo "source ${VIRTUAL_ENV}/bin/activate" >> /home/user/.bashrc

# Register the venv's Python interpreter with IDA so that idascript and
# qbinary can drive it programmatically.
# idapyswitch -a (auto) relies on python3-config which is not installed;
# instead point it directly to the system libpython via --force-path.
# libpython3.13 provides the shared library on Debian testing.
RUN libpython="$(find /usr /lib -name 'libpython3*.so*' 2>/dev/null | head -1)" && \
    [ -n "${libpython}" ] || { echo "ERROR: libpython not found"; exit 1; } && \
    "${IDA_INSTALL_DIR}/idapyswitch" --force-path "${libpython}"

CMD ["/bin/bash"]
