#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${1:-build}"

cmake -S . -B "${BUILD_DIR}"
cmake --build "${BUILD_DIR}" --target xdp_bytecode
cmake --build "${BUILD_DIR}" --target sk_msg_bytecode
