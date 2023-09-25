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

// Escape a string for use as an URL path segment. All characters in the extra
// string are escaped, even if they would not need to be by the spec, so that
// they can be used as delimiters, too.
//
// See: https://url.spec.whatwg.org/#url-path-segment-string
static char* urlescape_path(const char* src, const char* extra) {
  if (!src) return NULL;
  if (!extra) extra = "";

  // First pass: output length

  size_t output_length = 1;  // We need at least the trailing NUL byte.
  for (const char* c = src; *c != '\0'; c++) {
    if (!strchr(extra, *c) &&
        (isalnum(*c) || strchr(valid_url_path_chars, *c))) {
      output_length += 1;
    } else {
      output_length += escaped_char_length;
    }
  }
  char* dst = calloc(output_length, 1);
  if (!dst) return dst;

  // Second pass: copy over and escape

  int dst_offset = 0;
  for (const char* next_char = src; *next_char != '\0'; next_char++) {
    if (!strchr(extra, *next_char) &&
        (isalnum(*next_char) || strchr(valid_url_path_chars, *next_char))) {
      dst[dst_offset] = *next_char;
      dst_offset++;
    } else {
      snprintf(dst + dst_offset, escaped_char_length + 1, "%%%02X", *next_char);
      dst_offset += escaped_char_length;
    }
  }
  return dst;
}

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
