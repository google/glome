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

#ifndef GLOME_H_
#define GLOME_H_

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define GLOME_MAX_PUBLIC_KEY_LENGTH 32
#define GLOME_MAX_PRIVATE_KEY_LENGTH 32
#define GLOME_MAX_TAG_LENGTH 32

#ifdef __cplusplus
extern "C" {
#endif

// glome_generate_key generates a new Curve25519 key pair suitable for use
// with GLOME. Call this once per session to create an ephemeral identity; for
// long-lived service keys, store the private key securely and derive the
// public key with glome_derive_key instead.
//
// Parameters:
//   private_key - Output buffer of at least GLOME_MAX_PRIVATE_KEY_LENGTH bytes
//                 that receives the newly generated private key. The caller
//                 owns this buffer and is responsible for zeroing and freeing
//                 it when no longer needed.
//   public_key  - Output buffer of at least GLOME_MAX_PUBLIC_KEY_LENGTH bytes
//                 that receives the corresponding public key. The caller owns
//                 this buffer.
//
// Returns 0 on success, or a non-zero value if key generation fails (e.g. the
// underlying random number source is unavailable).
int glome_generate_key(uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                       uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH]);

// glome_derive_key derives the Curve25519 public key corresponding to a given
// private key. Use this to recover or publish the public half of a previously
// stored private key without regenerating the pair.
//
// Parameters:
//   private_key - Input buffer of at least GLOME_MAX_PRIVATE_KEY_LENGTH bytes
//                 containing the private key. The caller retains ownership;
//                 this function does not modify or store the private key.
//   public_key  - Output buffer of at least GLOME_MAX_PUBLIC_KEY_LENGTH bytes
//                 that receives the derived public key. The caller owns this
//                 buffer.
//
// Returns 0 on success, or a non-zero value if derivation fails.
int glome_derive_key(const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                     uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH]);

// glome_tag generates or verifies a GLOME authentication tag for a message.
// The tag has a size of GLOME_MAX_TAG_LENGTH bytes, computed over a shared
// secret derived from a Diffie-Hellman exchange between the local private key
// and the remote peer's public key.
//
// Use verify=false (tag generation) on the sending side to produce a tag that
// authenticates a message to the remote peer. Use verify=true (tag
// verification) on the receiving side to check that a tag received from the
// remote peer is valid for the given message and counter value.
//
// Parameters:
//   verify      - If false, generate a new tag and write it to `tag`.
//                 If true, verify the tag in `tag` against the message and
//                 return 0 on success or a non-zero value on mismatch.
//   counter     - A per-message counter used to prevent replay attacks.
//                 Both sides must agree on the counter value; it is typically
//                 incremented for each message exchanged in a session.
//   private_key - Input buffer of at least GLOME_MAX_PRIVATE_KEY_LENGTH bytes
//                 containing the local peer's private key. The caller retains
//                 ownership; this function does not modify or store it.
//   peer_key    - Input buffer of at least GLOME_MAX_PUBLIC_KEY_LENGTH bytes
//                 containing the remote peer's public key. The caller retains
//                 ownership; this function does not modify or store it.
//   message     - Pointer to the message bytes to authenticate. May be NULL
//                 if message_len is 0. The caller retains ownership.
//   message_len - Length of the message in bytes.
//   tag         - When verify=false: output buffer of at least
//                 GLOME_MAX_TAG_LENGTH bytes that receives the generated tag.
//                 The caller owns this buffer.
//                 When verify=true: input buffer of at least
//                 GLOME_MAX_TAG_LENGTH bytes containing the tag to verify.
//                 The caller retains ownership.
//
// Returns 0 on success. When verify=false, a non-zero value indicates a
// failure to compute the shared secret or tag. When verify=true, a non-zero
// value indicates that the tag is invalid or that computation failed.
int glome_tag(bool verify, unsigned char counter,
              const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
              const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
              const uint8_t *message, size_t message_len,
              uint8_t tag[GLOME_MAX_TAG_LENGTH]);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // GLOME_H_