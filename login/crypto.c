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

#include "crypto.h"

#include <glome.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int is_zeroed(const uint8_t* buf, size_t len) {
  int sum = 0;
  while (len > 0) {
    sum |= buf[--len];
  }
  return sum == 0;
}

int derive_or_generate_key(uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                           uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH]) {
  if (is_zeroed(private_key, PRIVATE_KEY_LENGTH)) {
    // New key pair needs to be generated...
    return glome_generate_key(private_key, public_key);
  } else {
    // ... unless a non-zero private key is provided.
    return glome_derive_key(private_key, public_key);
  }
}

static int login_tag(bool verify, const char* host_id, const char* action,
                     const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                     const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                     uint8_t output[GLOME_MAX_TAG_LENGTH]) {
  size_t message_len = strlen(host_id) + 1 + strlen(action) + 1;
  char* message = calloc(message_len, 1);
  if (message == NULL) {
    return -1;
  }
  int ret = snprintf(message, message_len, "%s/%s", host_id, action);
  if (ret < 0) {
    free(message);
    return -1;
  }
  if ((size_t) ret >= message_len) {
    free(message);
    return -1;
  }
  if (glome_tag(verify, 0, private_key, peer_key, (uint8_t*)message,
                strlen(message), output) != 0) {
    free(message);
    return -1;
  }

  free(message);
  return 0;
}

int get_authcode(const char* host_id, const char* action,
                 const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                 const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                 uint8_t authcode[GLOME_MAX_TAG_LENGTH]) {
  return login_tag(true, host_id, action, peer_key, private_key, authcode);
}

int get_msg_tag(const char* host_id, const char* action,
                const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                uint8_t tag[GLOME_MAX_TAG_LENGTH]) {
  return login_tag(false, host_id, action, peer_key, private_key, tag);
}
