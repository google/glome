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

#include "glome.h"

#include <assert.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <string.h>

#define X25519_SHARED_KEY_LEN 32

int glome_generate_key(uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                       uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH]) {
  size_t public_key_len = GLOME_MAX_PUBLIC_KEY_LENGTH;
  size_t private_key_len = GLOME_MAX_PRIVATE_KEY_LENGTH;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

  int err =
      (ctx == NULL || EVP_PKEY_keygen_init(ctx) != 1 ||
       EVP_PKEY_keygen(ctx, &pkey) != 1 ||
       EVP_PKEY_get_raw_public_key(pkey, public_key, &public_key_len) != 1 ||
       public_key_len != GLOME_MAX_PUBLIC_KEY_LENGTH ||
       EVP_PKEY_get_raw_private_key(pkey, private_key, &private_key_len) != 1 ||
       private_key_len != GLOME_MAX_PRIVATE_KEY_LENGTH);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return err;
}

int glome_derive_key(const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                     uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH]) {
  size_t public_key_length = GLOME_MAX_PUBLIC_KEY_LENGTH;

  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, NULL, private_key, GLOME_MAX_PRIVATE_KEY_LENGTH);
  int err =
      (pkey == NULL ||
       EVP_PKEY_get_raw_public_key(pkey, public_key, &public_key_length) != 1 ||
       public_key_length != GLOME_MAX_PUBLIC_KEY_LENGTH);
  EVP_PKEY_free(pkey);
  return err;
}

int glome_tag(bool verify, unsigned char counter,
              const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
              const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
              const uint8_t *message, size_t message_len,
              uint8_t tag[GLOME_MAX_TAG_LENGTH]) {
  uint8_t hmac_key[X25519_SHARED_KEY_LEN + 2 * GLOME_MAX_PUBLIC_KEY_LENGTH] = {
      0};
  uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};

  EVP_PKEY *evp_peer_key = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, NULL, peer_key, GLOME_MAX_PUBLIC_KEY_LENGTH);

  EVP_PKEY *evp_private_key = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, NULL, private_key, GLOME_MAX_PRIVATE_KEY_LENGTH);

  if (evp_private_key == NULL || evp_peer_key == NULL) {
    EVP_PKEY_free(evp_peer_key);
    EVP_PKEY_free(evp_private_key);
    return 1;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_private_key, NULL);
  if (ctx == NULL) {
    EVP_PKEY_free(evp_peer_key);
    EVP_PKEY_free(evp_private_key);
    return 1;
  }

  // Derive public key.
  size_t public_key_length = GLOME_MAX_PUBLIC_KEY_LENGTH;
  int err = (EVP_PKEY_get_raw_public_key(evp_private_key, public_key,
                                         &public_key_length) != 1 ||
             public_key_length != GLOME_MAX_PUBLIC_KEY_LENGTH);
  if (err) {
    EVP_PKEY_free(evp_peer_key);
    EVP_PKEY_free(evp_private_key);
    return 1;
  }

  // X25519 shared secret
  size_t shared_key_length = X25519_SHARED_KEY_LEN;
  err = (EVP_PKEY_derive_init(ctx) != 1 ||
         EVP_PKEY_derive_set_peer(ctx, evp_peer_key) != 1 ||
         EVP_PKEY_derive(ctx, hmac_key, &shared_key_length) != 1 ||
         shared_key_length != X25519_SHARED_KEY_LEN);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(evp_peer_key);
  EVP_PKEY_free(evp_private_key);

  if (err) {
    return 1;
  }

  // hmac_key := (sharded_key | verifier_key | signer_key)
  memcpy(hmac_key + X25519_SHARED_KEY_LEN, (verify ? public_key : peer_key),
         GLOME_MAX_PUBLIC_KEY_LENGTH);
  memcpy(hmac_key + X25519_SHARED_KEY_LEN + GLOME_MAX_PUBLIC_KEY_LENGTH,
         (verify ? peer_key : public_key), GLOME_MAX_PUBLIC_KEY_LENGTH);

  HMAC_CTX *hmac_ctx = HMAC_CTX_new();
  unsigned int tag_length = GLOME_MAX_TAG_LENGTH;
  int success =
      (HMAC_Init_ex(hmac_ctx, hmac_key, sizeof hmac_key, EVP_sha256(), NULL) &&
       HMAC_Update(hmac_ctx, &counter, sizeof counter) &&
       HMAC_Update(hmac_ctx, message, message_len) &&
       HMAC_Final(hmac_ctx, tag, &tag_length) &&
       tag_length == GLOME_MAX_TAG_LENGTH);
  HMAC_CTX_free(hmac_ctx);
  return success ? 0 : 1;
}
