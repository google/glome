#!/bin/sh
set -e

apk add --no-cache \
  alpine-sdk meson pandoc-cli \
  openssl-dev glib-dev linux-pam-dev
