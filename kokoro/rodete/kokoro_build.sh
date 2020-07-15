#!/bin/bash
set -e

sudo apt-get install -y build-essential meson pkg-config libssl-dev libconfuse-dev

cd "${KOKORO_ARTIFACTS_DIR}"/piper/google3/third_party/glome
meson build

cd build/
ninja
meson test
