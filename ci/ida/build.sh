#!/usr/bin/env bash
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

# Build one Docker image per requested IDA version. Each version is built from
# its own installer file (ida-pro_<VER>.run) located next to this script.
# Produced images are tagged <name>:<VER>; the numerically greatest version is
# additionally tagged <name>:latest.
#
# IDA 9.x requires interactive EULA acceptance before it writes ida.reg.
# The build therefore proceeds in two phases per version:
#   Phase 1 — build a setup image without ida.reg, run it interactively so
#              the user can accept the EULA, then extract the resulting ida.reg
#              from the stopped container. Skipped if ida_<VER>.reg already
#              exists on disk from a prior run.
#   Phase 2 — build the final image via Dockerfile.final, which extends the
#              setup image and injects ida.reg.
#
# The installer is passed via bind-mount (no size limit, never committed to any
# layer). It must be located next to this script as ida-pro_<VER>.run.
# The licence file (idapro.hexlic) is NEVER baked into any image layer.
# Pass it at runtime via a Docker secret:
#   docker run --mount type=secret,id=ida_license,src=idapro.hexlic <name>:<VER>

set -euo pipefail

# ── Docker command resolution ─────────────────────────────────────────────────

# Determine whether docker must be run via sudo. A plain `docker info` is
# attempted first; if it fails (e.g. the current user is not in the docker
# group), sudo is prepended for all subsequent docker calls.
if docker info > /dev/null 2>&1; then
    DOCKER="docker"
elif sudo docker info > /dev/null 2>&1; then
    DOCKER="sudo docker"
else
    echo "ERROR: Cannot connect to the Docker daemon (tried both 'docker' and 'sudo docker')." >&2
    exit 1
fi
readonly DOCKER

# ── Constants ─────────────────────────────────────────────────────────────────

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DOCKERFILE="${SCRIPT_DIR}/Dockerfile"
readonly DOCKERFILE_FINAL="${SCRIPT_DIR}/Dockerfile.final"
readonly DEFAULT_LICENSE="${SCRIPT_DIR}/idapro.hexlic"
readonly IMAGE_NAME_DEFAULT="ida"

# ── Helpers ───────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage:
  $(basename "$0") --version <VER> [--version <VER> ...] [OPTIONS]

Build one Docker image per requested IDA version. Each version is built from
its own installer file (ida-pro_<VER>.run) located next to this script.
Produced images are tagged <name>:<VER>; the numerically greatest version is
additionally tagged <name>:latest.

IDA 9.x requires interactive EULA acceptance on first launch. The build runs
in two phases: phase 1 launches IDA so you can accept the EULA and extracts
the resulting ida.reg; phase 2 builds the final image with ida.reg injected.
Phase 1 is skipped if ida_<VER>.reg already exists from a prior run.

The licence file (idapro.hexlic) is NEVER baked into any image layer.
Pass it at runtime via a Docker secret:
  docker run --mount type=secret,id=ida_license,src=idapro.hexlic <name>:<VER>

The installer is passed via bind-mount and is never committed to any layer.

Options:
  -v, --version <VER>    IDA version number (e.g. 91). Repeatable.
                         Installer resolved as ./ida-pro_<VER>.run.
  -n, --name    <name>   Base image name (default: pyrrha-ida).
                         Images tagged <name>:<VER>, newest also <name>:latest.
  -l, --license <path>   Path to idapro.hexlic (default: ./idapro.hexlic).
                         Validated at startup, never passed to docker build.
  -h, --help             Print this help and exit.

Examples:
  # Build a single version with defaults:
  $(basename "$0") --version 91

  # Build two versions under a custom image name:
  $(basename "$0") --version 91 --version 92 --name myorg/ida

  # Build with a licence file stored elsewhere:
  $(basename "$0") --version 91 --license /secure/idapro.hexlic
EOF
    exit 0
}

die() {
    echo "ERROR: $*" >&2
    echo >&2
    usage
    exit 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────

versions=()
image_name="${IMAGE_NAME_DEFAULT}"
license_path="${DEFAULT_LICENSE}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--version)
            [[ -n "${2:-}" ]] || die "--version requires an argument."
            versions+=("$2")
            shift 2
            ;;
        -n|--name)
            [[ -n "${2:-}" ]] || die "--name requires an argument."
            image_name="$2"
            shift 2
            ;;
        -l|--license)
            [[ -n "${2:-}" ]] || die "--license requires an argument."
            license_path="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

[[ ${#versions[@]} -gt 0 ]] || die "At least one --version is required."

# ── Pre-flight checks ─────────────────────────────────────────────────────────

[[ -f "${DOCKERFILE}" ]]       || die "Dockerfile not found at: ${DOCKERFILE}"
[[ -f "${DOCKERFILE_FINAL}" ]] || die "Dockerfile.final not found at: ${DOCKERFILE_FINAL}"
[[ -f "${license_path}" ]]     || die "Licence file not found at: ${license_path}"

# ── Build loop ────────────────────────────────────────────────────────────────

# The latest version is the numerically greatest one; it will also be tagged
# as :latest after its build.
latest_version="$(printf '%s\n' "${versions[@]}" | sort -n | tail -1)"

for version in "${versions[@]}"; do
    # Each version has its own installer: ida-pro_<VER>.run
    installer_path="${SCRIPT_DIR}/ida-pro_${version}.run"

    [[ -f "${installer_path}" ]] || \
        die "Installer not found for version ${version}: ${installer_path}"

    # IDA_INSTALLER is a plain filename relative to the build context so that
    # Docker bind-mounting the context can resolve it without path doubling.
    installer_filename="$(basename "${installer_path}")"

    image_tag="${image_name}:${version}"
    tmp_image="${image_name}:${version}-setup"
    tmp_container="ida-setup-${version}"
    ida_reg_path="${SCRIPT_DIR}/ida_${version}.reg"

    echo "==> Building ${image_tag}"
    echo "    Installer : ${installer_path}"
    echo "    Licence   : ${license_path}"
    echo "    ida.reg   : ${ida_reg_path} (exists: $([ -f "${ida_reg_path}" ] && echo yes || echo no))"

    # ── Phase 1: build setup image and extract ida.reg ────────────────────
    # IDA 9.x requires interactive EULA acceptance before writing ida.reg.
    # Skipped if ida_<VER>.reg already exists from a prior run.
    if [[ ! -f "${ida_reg_path}" ]]; then
        echo "==> [Phase 1] ida.reg not found at ${ida_reg_path}, running setup..."

        echo "==> [Phase 1] Building setup image ${tmp_image}..."
        ${DOCKER} build \
            --build-arg "IDA_VERSION=${version}" \
            --build-arg "IDA_INSTALLER=${installer_filename}" \
            --tag "${tmp_image}" \
            --file "${DOCKERFILE}" \
            "${SCRIPT_DIR}"

        echo "==> [Phase 1] Starting temporary container."
        echo "    Accept the IDA EULA when prompted, then close IDA."
        echo "    The container will stop automatically afterwards."

        # Remove any leftover container from a previous failed attempt.
        ${DOCKER} rm "${tmp_container}" 2>/dev/null || true

        # Find the IDA GUI binary. In IDA 9.x it is simply 'ida' (no suffix);
        # older versions used 'ida64'. We match exactly those two names.
        ida_binary="$(${DOCKER} run --rm "${tmp_image}" \
            find "/opt/ida_${version}" -maxdepth 1 -type f -executable \
                \( -name 'ida' -o -name 'ida64' \) | head -1)"
        [[ -n "${ida_binary}" ]] || \
            die "Could not find IDA GUI binary (ida or ida64) in /opt/ida_${version}."
        echo "    IDA binary: ${ida_binary}"

        # Allow the root-owned Docker container to connect to the user's X
        # display. Revoked immediately after the container stops.
        xhost +local:root

        # Do NOT use --rm: we need the stopped container's filesystem to
        # extract ida.reg after the user has accepted the EULA and closed IDA.
        # Note: docker run does not support --mount type=secret (build-only);
        # the licence is passed as a read-only bind mount instead.
        # '|| true' prevents set -e from aborting the script when IDA exits
        # with a non-zero code (which it does on normal close).
        ${DOCKER} run --name "${tmp_container}" \
            -v "${license_path}:/run/secrets/ida_license:ro" \
            -e DISPLAY="${DISPLAY:-:0}" \
            -v /tmp/.X11-unix:/tmp/.X11-unix \
            "${tmp_image}" \
            "${ida_binary}" || true

        # Revoke the X display permission as soon as the container exits.
        xhost -local:root

        echo "==> [Phase 1] Container stopped. Extracting ida.reg..."
        ${DOCKER} cp "${tmp_container}:/home/user/.idapro/ida.reg" "${ida_reg_path}" || \
            die "docker cp failed — ida.reg not found in container '${tmp_container}'." \
                "Make sure you accepted the EULA and closed IDA before the container exited."

        [[ -f "${ida_reg_path}" ]] || \
            die "ida.reg was not saved to ${ida_reg_path} after docker cp."

        ${DOCKER} rm "${tmp_container}"
        ${DOCKER} rmi "${tmp_image}" 2>/dev/null || true
        echo "==> [Phase 1] ida.reg saved to: ${ida_reg_path}"
    else
        echo "==> [Phase 1] Skipped — ida.reg already exists at: ${ida_reg_path}"
    fi

    # ── Phase 2: build the final image with ida.reg injected ─────────────
    # Uses Dockerfile.final which extends the setup image and only adds
    # ida.reg, avoiding the COPY-in-wrong-stage problem of a single Dockerfile.
    echo "==> [Phase 2] Building final image ${image_tag}..."

    cp "${ida_reg_path}" "${SCRIPT_DIR}/ida.reg" || \
        die "Failed to copy ${ida_reg_path} into build context."
    [[ -f "${SCRIPT_DIR}/ida.reg" ]] || \
        die "ida.reg is missing from build context (${SCRIPT_DIR}/ida.reg)."

    # Pass the md5 hash of ida.reg as a build arg to bust the Docker cache at
    # the COPY instruction, preventing reuse of a layer built before the file
    # existed.
    ida_reg_hash="$(md5sum "${SCRIPT_DIR}/ida.reg" | cut -d' ' -f1)"

    # Phase 2 needs the setup image as its base; build it if it was cleaned up.
    if ! ${DOCKER} image inspect "${tmp_image}" > /dev/null 2>&1; then
        echo "==> [Phase 2] Setup image not found, rebuilding ${tmp_image}..."
        ${DOCKER} build \
            --build-arg "IDA_VERSION=${version}" \
            --build-arg "IDA_INSTALLER=${installer_filename}" \
            --tag "${tmp_image}" \
            --file "${DOCKERFILE}" \
            "${SCRIPT_DIR}"
    fi
    ${DOCKER} build \
        --build-arg "IMAGE_NAME=${image_name}" \
        --build-arg "IDA_VERSION=${version}" \
        --build-arg "IDA_REG_HASH=${ida_reg_hash}" \
        --tag "${image_tag}" \
        --file "${DOCKERFILE_FINAL}" \
        "${SCRIPT_DIR}"

    rm -f "${SCRIPT_DIR}/ida.reg"

    # Tag the newest version as :latest.
    if [[ "${version}" == "${latest_version}" ]]; then
        ${DOCKER} tag "${image_tag}" "${image_name}:latest"
        echo "==> Also tagged ${image_tag} as ${image_name}:latest"
    fi

    echo "==> Successfully built ${image_tag}"
done

echo "==> Done."
