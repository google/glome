#!/bin/sh
set -e

apk add --no-cache \
  alpine-sdk meson \
  openssl-dev confuse-dev glib-dev linux-pam-dev
