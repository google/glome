#!/usr/bin/env bash
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

binary="$(realpath ${1?})"
iterations="${2:-0}"

if [[ ! -x "$binary" ]]; then
  echo "ERROR: $binary is not an executable"
  exit 1
fi

if (( iterations < 0 || iterations > 255 )); then
  echo "ERROR: the number of iterations must be within 0..255 (was: $iterations)"
  exit 2
fi

errors=0
t=$(mktemp -d glometest.XXX)
trap "rm -rf -- '${t?}'" EXIT

for side in 0 1; do
        "$binary" genkey | tee "${t}/${side}" | "$binary" pubkey >"${t}/${side}.pub"
done

for counter in $(seq 0 "$iterations"); do
  msg="$RANDOM"
  for side in 0 1; do
    peer=$((1 - "$side"))
    tag=$(printf %s "$msg" | "$binary" tag --key "${t}/${side}" --peer "${t}/${peer}.pub" --counter "$counter")
    for len in $(seq 2 2 64); do
      if ! printf %s "$msg" | "$binary" verify -k "${t}/${peer}" -p "${t}/${side}.pub" -c "$counter" -t "${tag:0:$len}"; then
        let errors++
        echo "FAIL: side=${side} peer=${peer} msg=${msg} counter=${counter}"
      fi
      if printf %s "wrong-$msg" | "$binary" verify -k "${t}/${peer}" -p "${t}/${side}.pub" -c "$counter" -t "${tag:0:$len}"; then
        let errors++
        echo "FAIL: incorrectly verified! side=${side} peer=${peer} msg=${msg} counter=${counter}"
      fi
    done
  done
done

echo "$errors errors"
exit "$errors"
