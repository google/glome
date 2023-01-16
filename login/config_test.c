// Copyright 2023 Google LLC
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

#include "config.h"

#include <stdio.h>

#include <glib.h>

static const char* ENCODED_PUBLIC_KEY = "glome-v1 aqA9yqe1RXoOT6HrmCbF40wVUhYp50FYZR9q8_X5KF4=";

static const uint8_t DECODED_PUBLIC_KEY[32] = {0x6a, 0xa0, 0x3d, 0xca, 0xa7, 0xb5, 0x45, 0x7a, 0x0e, 0x4f, 0xa1, 0xeb, 0x98, 0x26, 0xc5, 0xe3, 0x4c, 0x15, 0x52, 0x16, 0x29, 0xe7, 0x41, 0x58, 0x65, 0x1f, 0x6a, 0xf3, 0xf5, 0xf9, 0x28, 0x5e};

static void test_parse_public_key() {
  uint8_t decoded[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  g_assert_true(
      glome_login_parse_public_key(ENCODED_PUBLIC_KEY, decoded, sizeof(decoded)));
  g_assert_cmpmem(decoded, sizeof(decoded), DECODED_PUBLIC_KEY, sizeof(DECODED_PUBLIC_KEY));

  g_assert_false(
      glome_login_parse_public_key(ENCODED_PUBLIC_KEY, decoded, sizeof(decoded) - 1));
  g_assert_false(glome_login_parse_public_key(
      "glome-group1-md5 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=", decoded,
      sizeof(decoded)));
  g_assert_false(glome_login_parse_public_key("glome-v1 QUFBQUFBQUFB", decoded,
                                              sizeof(decoded)));

  memset(decoded, 0, sizeof(decoded));
  const char* extra_chars =
      "glome-v1 \t aqA9yqe1RXoOT6HrmCbF40wVUhYp50FYZR9q8_X5KF4= "
      "root@localhost";
  g_assert_true(
      glome_login_parse_public_key(extra_chars, decoded, sizeof(decoded)));
  g_assert_cmpmem(decoded, sizeof(decoded), DECODED_PUBLIC_KEY, sizeof(DECODED_PUBLIC_KEY));
}

int main(int argc, char** argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/test-parse-public-key", test_parse_public_key);

  return g_test_run();
}