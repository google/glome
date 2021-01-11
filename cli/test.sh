#!/bin/sh
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eu

binary="$(dirname "$1")/$(basename "$1")"
iterations="${2:-0}"

if ! test -x "$binary"; then
  echo "ERROR: $binary is not an executable"
  exit 1
fi

if [ "$iterations" -lt 0 ] || [ "$iterations" -gt 255 ]; then
  echo "ERROR: the number of iterations must be within 0..255 (was: $iterations)"
  exit 2
fi

t=$(mktemp -d)
cleanup() {
  rm -rf -- "${t?}"
}
trap cleanup EXIT

for side in 0 1; do
        "$binary" genkey | tee "${t}/${side}" | "$binary" pubkey >"${t}/${side}.pub"
done

errors=0
for counter in $(seq 0 "$iterations"); do
  msg="$(head -c 2 /dev/urandom | od -t u2 -A n)"
  for side in 0 1; do
    peer=$((1 - side))
    tag=$(printf %s "$msg" | "$binary" tag --key "${t}/${side}" --peer "${t}/${peer}.pub" --counter "$counter")
    for len in $(seq 2 2 64); do
      shorttag=$(printf %s "$tag" | head -c "$len")
      if ! printf %s "$msg" | "$binary" verify -k "${t}/${peer}" -p "${t}/${side}.pub" -c "$counter" -t "${shorttag}"; then
        errors=$((errors + 1))
        echo "FAIL: side=${side} peer=${peer} msg=${msg} counter=${counter}"
      fi
      if printf %s "wrong-$msg" | "$binary" verify -k "${t}/${peer}" -p "${t}/${side}.pub" -c "$counter" -t "${shorttag}"; then
        errors=$((errors + 1))
        echo "FAIL: incorrectly verified! side=${side} peer=${peer} msg=${msg} counter=${counter}"
      fi
    done
  done
done

echo "$errors errors"
exit "$errors"
