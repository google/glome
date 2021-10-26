#!/bin/sh
# Copyright 2021 Google LLC
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

if ! test -x "$binary"; then
  echo "ERROR: $binary is not an executable" >&2
  exit 1
fi

t=$(mktemp -d)
cleanup() {
  rm -rf -- "${t?}"
}
trap cleanup EXIT

# Populate directory with keys according to specification.
mkdir -p "$t/vector-1"
printf '\167\007\155\012\163\030\245\175\074\026\301\162\121\262\146\105\337'\
'\114\057\207\353\300\231\052\261\167\373\245\035\271\054\052' >"$t/vector-1/a"
printf '\135\253\010\176\142\112\212\113\171\341\177\213\203\200\016\346\157'\
'\073\261\051\046\030\266\375\034\057\213\047\377\210\340\353' >"$t/vector-1/b"
printf "The quick brown fox" >"$t/vector-1/msg"
printf "0" >"$t/vector-1/n"
printf "9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3" >"$t/vector-1/tag"

mkdir -p "$t/vector-2"
printf '\261\005\360\015\261\005\360\015\261\005\360\015\261\005\360\015\261'\
'\005\360\015\261\005\360\015\261\005\360\015\261\005\360\015' >"$t/vector-2/a"
printf '\376\341\336\255\376\341\336\255\376\341\336\255\376\341\336\255\376'\
'\341\336\255\376\341\336\255\376\341\336\255\376\341\336\255' >"$t/vector-2/b"
printf "The quick brown fox" >"$t/vector-2/msg"
printf "100" >"$t/vector-2/n"
printf "06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277" >"$t/vector-2/tag"

errors=0
for n in 1 2; do
  testdir="$t/vector-$n"
  counter=$(cat "$testdir/n")
  expected_tag="$(cat "$testdir/tag")"
  for x in a b; do
    "$binary" pubkey <"$testdir/$x" >"$testdir/$x.pub"
  done
  tag=$("$binary" tag --key "$testdir/a" --peer "$testdir/b.pub" --counter "$counter" <"$testdir/msg")
  if [ "$tag" != "${expected_tag}" ]; then
    echo "Generated wrong tag for test vector $n" >&2
    echo "${expected_tag} <- expected" >&2
    echo "$tag <- actual" >&2
    errors=$((errors + 1))
  fi
  if ! "$binary" verify -k "$testdir/b" -p "$testdir/a.pub" -c "$counter" -t "$tag" <"$testdir/msg"; then
    echo "Failed to verify test vector $n" >&2
    errors=$((errors + 1))
  fi
done

# Test login subcommand according to specification.
key="$t/vector-1/b"
path="/v1/AYUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q0PU=/my-server.local/shell/root/"
expected_tag="lyHuaHuCcknb5sJEukWSFs8B1SUBIWMCXfNY64fIkFk="
tag=$("$binary" login --key "$key" "$path")
if [ "$tag" != "$expected_tag" ]; then
    echo "Generated wrong tag for test path $path" >&2
    echo "$expected_tag <- expected" >&2
    echo "$tag <- actual" >&2
    errors=$((errors + 1))
fi

key="$t/vector-2/a"
path="/v1/UYcvQ1u4uJ0OOtYqouURB07hleHDnvaogAFBi-ZW48N2/serial-number:1234567890=ABCDFGH%2F%23%3F/reboot/"
expected_tag="p8M_BUKj7zXBVM2JlQhNYFxs4J-DzxRAps83ZaNDquY="
tag=$("$binary" login --key "$key" "$path")
if [ "$tag" != "$expected_tag" ]; then
    echo "Generated wrong tag for test path $path" >&2
    echo "$expected_tag <- expected" >&2
    echo "$tag <- actual" >&2
    errors=$((errors + 1))
fi

exit "$errors"
