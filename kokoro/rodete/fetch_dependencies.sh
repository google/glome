#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y \
  build-essential meson pkg-config \
  libssl-dev libconfuse-dev
