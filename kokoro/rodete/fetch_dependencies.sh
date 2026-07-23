#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  build-essential meson pkg-config pandoc \
  libssl-dev libglib2.0-dev libpam0g-dev libpam-wrapper libpamtest0-dev \
  cargo rustc librust-base64-dev librust-clap-derive-dev librust-clap-dev \
  librust-hmac-dev librust-sha2-dev librust-x25519-dalek-dev libstd-rust-dev \
  librust-hex-dev librust-hex-literal-dev librust-tempfile-dev librust-yaml-rust2-dev
