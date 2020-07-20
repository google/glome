#!/bin/bash
set -e

cd "${KOKORO_ARTIFACTS_DIR}"/piper/google3/third_party/glome

sudo ./kokoro/rodete/fetch_dependencies.sh

meson build
ninja -C build
meson test -C build
