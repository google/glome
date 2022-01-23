#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  build-essential meson pkg-config \
  libssl-dev libglib2.0-dev libpam0g-dev libpam-wrapper
