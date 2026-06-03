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

# Build a Docker image with Ghidra and pyrrha-mapper.
#
# The Ghidra release is downloaded and verified at build time — no local
# installer file is required. The produced image is tagged <n>:<VER>.
#
# Usage:
#   ./build_ghidra.sh [OPTIONS]
#
# Options:
#   -v, --version  <VER>    Ghidra version (default: 12.0.4).
#   -d, --date     <DATE>   Ghidra release date string (default: 20260303).
#   -s, --sha256   <SHA>    Expected SHA-256 of the Ghidra zip (required when
#                           overriding --version, to ensure integrity).
#   -n, --name     <n>      Base image name (default: pyrrha-ghidra).
#                           Image tagged <n>:<VER>, also <n>:latest.
#   -h, --help              Print this help and exit.
#
# Examples:
#   # Build with defaults:
#   ./build_ghidra.sh
#
#   # Build a specific version:
#   ./build_ghidra.sh --version 12.0.4 --date 20260303 \
#       --sha256 c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120
#
#   # Build under a custom image name:
#   ./build_ghidra.sh --name myorg/ghidra

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
readonly IMAGE_NAME_DEFAULT="ghidra"

# Default Ghidra release — update these when a new version is published.
readonly DEFAULT_VERSION="12.0.4"
readonly DEFAULT_DATE="20260303"
readonly DEFAULT_SHA256="c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120"

# ── Helpers ───────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage:
  $(basename "$0") [OPTIONS]

Build a Docker image containing Ghidra and pyrrha-mapper. The Ghidra release
is downloaded and SHA-256 verified at build time.

The produced image is tagged <n>:<VER> and also <n>:latest.

Options:
  -v, --version <VER>    Ghidra version (default: ${DEFAULT_VERSION}).
  -d, --date    <DATE>   Ghidra release date string (default: ${DEFAULT_DATE}).
  -s, --sha256  <SHA>    Expected SHA-256 of the Ghidra zip.
                         Required when overriding --version.
                         Default: ${DEFAULT_SHA256}
  -n, --name    <n>      Base image name (default: ${IMAGE_NAME_DEFAULT}).
                         Image tagged <n>:<VER> and <n>:latest.
  -h, --help             Print this help and exit.

Examples:
  # Build with defaults:
  $(basename "$0")

  # Build a specific version:
  $(basename "$0") --version 12.0.4 --date 20260303 \\
      --sha256 c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120

  # Build under a custom image name:
  $(basename "$0") --name myorg/ghidra
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

ghidra_version="${DEFAULT_VERSION}"
ghidra_date="${DEFAULT_DATE}"
ghidra_sha256="${DEFAULT_SHA256}"
image_name="${IMAGE_NAME_DEFAULT}"
version_overridden=false
sha256_overridden=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--version)
            [[ -n "${2:-}" ]] || die "--version requires an argument."
            ghidra_version="$2"
            version_overridden=true
            shift 2
            ;;
        -d|--date)
            [[ -n "${2:-}" ]] || die "--date requires an argument."
            ghidra_date="$2"
            shift 2
            ;;
        -s|--sha256)
            [[ -n "${2:-}" ]] || die "--sha256 requires an argument."
            ghidra_sha256="$2"
            sha256_overridden=true
            shift 2
            ;;
        -n|--name)
            [[ -n "${2:-}" ]] || die "--name requires an argument."
            image_name="$2"
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

# If the user overrode --version but not --sha256, the default SHA-256 is
# almost certainly wrong for a different version.
if [[ "${version_overridden}" == true && "${sha256_overridden}" == false ]]; then
    die "You overrode --version but not --sha256. " \
        "Please provide the correct SHA-256 for Ghidra ${ghidra_version} via --sha256."
fi

# ── Pre-flight checks ─────────────────────────────────────────────────────────

[[ -f "${DOCKERFILE}" ]] || die "Dockerfile not found at: ${DOCKERFILE}"

# ── Build ─────────────────────────────────────────────────────────────────────

image_tag="${image_name}:${ghidra_version}"

echo "==> Building ${image_tag}"
echo "    Ghidra version : ${ghidra_version}"
echo "    Release date   : ${ghidra_date}"
echo "    SHA-256        : ${ghidra_sha256}"

${DOCKER} build \
    --build-arg "GHIDRA_VERSION=${ghidra_version}" \
    --build-arg "GHIDRA_RELEASE_DATE=${ghidra_date}" \
    --build-arg "GHIDRA_SHA256=${ghidra_sha256}" \
    --tag "${image_tag}" \
    --file "${DOCKERFILE}" \
    "${SCRIPT_DIR}"

${DOCKER} tag "${image_tag}" "${image_name}:latest"

echo "==> Successfully built ${image_tag}"
echo "==> Also tagged as ${image_name}:latest"
echo "==> Done."