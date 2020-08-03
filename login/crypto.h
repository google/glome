// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef CRYPTO_H_
#define CRYPTO_H_
#include <glome.h>
#include <inttypes.h>
#include <stddef.h>

#define PUBLIC_KEY_LENGTH 32
#define PRIVATE_KEY_LENGTH 32
#define SHARED_KEY_LENGTH 32

// Given a private key, derive the corresponding public key.
// If given an private key consisting of all zeroes a new private
// key will be generated in addition to the public key derivation.
int derive_or_generate_key(uint8_t private_key[PRIVATE_KEY_LENGTH],
                           uint8_t public_key[PUBLIC_KEY_LENGTH]);

int get_authcode(const char* host_id, const char* action,
                 const uint8_t peer_key[PUBLIC_KEY_LENGTH],
                 const uint8_t private_key[PRIVATE_KEY_LENGTH],
                 uint8_t authcode[GLOME_MAX_TAG_LENGTH]);

int get_msg_tag(const char* host_id, const char* action,
                const uint8_t peer_key[PUBLIC_KEY_LENGTH],
                const uint8_t private_key[PRIVATE_KEY_LENGTH],
                uint8_t tag[GLOME_MAX_TAG_LENGTH]);

// is_zeroed() checks (in constant time) if all len bytes of buf are zeros.
// This is to avoid timing attacks.
int is_zeroed(const uint8_t* buf, size_t len);

#endif  // CRYPTO_H_
