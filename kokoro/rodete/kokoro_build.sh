#!/bin/bash
set -e

cd "${KOKORO_ARTIFACTS_DIR}"/piper/google3/third_party/glome

sudo ./kokoro/rodete/fetch_dependencies.sh

# Internal Google builds requires the glib.h file to be present at
# third_party/glib/glib/glib.h
GLIB_DIR=$(dirname $(dpkg -S '*/glib.h' | awk '{print $2; exit}'))
mkdir -p third_party/glib/
ln -sf "${GLIB_DIR}" third_party/glib/glib

meson build
ninja -C build
meson test -C build
