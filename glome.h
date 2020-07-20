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

#ifndef GLOME_H
#define GLOME_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define GLOME_MAX_PUBLIC_KEY_LENGTH 32
#define GLOME_MAX_PRIVATE_KEY_LENGTH 32
#define GLOME_MAX_TAG_LENGTH 32

#ifdef __cplusplus
extern "C" {
#endif

// Generates a new public/private key pair for use with GLOME.
int glome_generate_key(uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                       uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH]);

// Derives the public key from the private key.
int glome_derive_key(const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                     uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH]);

// Generates or verifies the GLOME tag for the message. Requires passing in the
// private key of the local peer and the public key of the remote peer.
int glome_tag(bool verify, unsigned char counter,
              const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
              const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
              const uint8_t *message, size_t message_len,
              uint8_t tag[GLOME_MAX_TAG_LENGTH]);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // GLOME_H
