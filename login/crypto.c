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

#include <ctype.h>
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

static const char* valid_url_path_chars = "-._~!$&'()*+,;=";

static const size_t escaped_char_length = 3;

// TODO: document
static char* urlescape_path(const char* raw, const char* extra) {
  if (!raw) return NULL;
  if (!extra) extra = "";

  // TODO: find better variable names in this function.

  size_t n = 1;
  for (const char* c = raw; *c != '\0'; c++) {
    if (!strchr(extra, *c) &&
        (isalnum(*c) || strchr(valid_url_path_chars, *c))) {
      n += 1;
    } else {
      n += escaped_char_length;
    }
  }
  char* ret = calloc(n, 1);
  if (!ret) return ret;

  char* r = ret;
  for (const char* c = raw; *c != '\0'; c++) {
    if (!strchr(extra, *c) &&
        (isalnum(*c) || strchr(valid_url_path_chars, *c))) {
      *r = *c;
      r++;
    } else {
      snprintf(r, escaped_char_length + 1, "%%%02X", *c);
      r += escaped_char_length;
    }
  }
  return ret;
}

// TODO: document
char* glome_login_message(const char* host_id_type, const char* host_id,
                          const char* action) {
  char *host_id_type_escaped = NULL, *host_id_escaped = NULL,
       *action_escaped = NULL, *message = NULL;

  host_id_escaped = urlescape_path(host_id, ":");
  action_escaped = urlescape_path(action, "");
  if (!host_id_escaped || !action_escaped) goto end;

  size_t message_len = strlen(host_id_escaped) + 1 + strlen(action_escaped) + 1;

  // Only prefix host_id_type if it's not empty.
  if (host_id_type && *host_id_type) {
    host_id_type_escaped = urlescape_path(host_id_type, ":");
    if (!host_id_type_escaped) goto end;
    message_len += strlen(host_id_type_escaped) + 1;
  }

  message = calloc(message_len, 1);
  if (message == NULL) {
    goto end;
  }

  char* dst = message;
  if (host_id_type_escaped) {
    dst = stpcpy(dst, host_id_type_escaped);
    *(dst++) = ':';
  }
  dst = stpcpy(dst, host_id_escaped);
  *(dst++) = '/';
  dst = stpcpy(dst, action_escaped);

end:
  free(host_id_type_escaped);
  free(host_id_escaped);
  free(action_escaped);
  return message;
}

// TODO: inline all functions below.

static int login_tag(bool verify, const char* host_id_type, const char* host_id,
                     const char* action,
                     const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                     const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                     uint8_t output[GLOME_MAX_TAG_LENGTH]) {
  char* message = glome_login_message(host_id_type, host_id, action);
  if (!message) return -1;

  if (glome_tag(verify, 0, private_key, peer_key, (uint8_t*)message,
                strlen(message), output) != 0) {
    free(message);
    return -1;
  }

  free(message);
  return 0;
}

int get_authcode(const char* host_id_type, const char* host_id,
                 const char* action,
                 const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                 const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                 uint8_t authcode[GLOME_MAX_TAG_LENGTH]) {
  return login_tag(true, host_id_type, host_id, action, peer_key, private_key,
                   authcode);
}

int get_msg_tag(const char* host_id_type, const char* host_id,
                const char* action,
                const uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                const uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH],
                uint8_t tag[GLOME_MAX_TAG_LENGTH]) {
  return login_tag(false, host_id_type, host_id, action, peer_key, private_key,
                   tag);
}
