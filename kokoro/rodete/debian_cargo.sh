#!/bin/sh

set -x

export CARGO="${CARGO:-/usr/share/cargo/bin/cargo}"
export CARGO_HOME="${CARGO_HOME:-$PWD/debian/cargo_home}"
export CARGO_REGISTRY="${CARGO_REGISTRY:-$PWD/debian/cargo_registry}"
export CFLAGS="${CFLAGS:-}"
export CXXFLAGS="${CXXFLAGS:-}"
export CPPFLAGS="${CPPFLAGS:-}"
export LDFLAGS="${LDFLAGS:-}"
export DEB_CARGO_CRATE="${DEB_CARGO_CRATE:-glome_0}"
export DEB_CARGO_INSTALL_PREFIX="${DEB_CARGO_INSTALL_PREFIX:-/usr/local}"

eval "$(dpkg-architecture -s)"
export DEB_HOST_GNU_TYPE

# shellcheck disable=SC2016
DEB_HOST_RUST_TYPE="$(printf 'include /usr/share/rustc/architecture.mk\nall:\n\techo $(DEB_HOST_RUST_TYPE)\n' | make --no-print-directory -sf -)"
export DEB_HOST_RUST_TYPE

rm -f rust/Cargo.lock
cd rust && $CARGO "$@"
