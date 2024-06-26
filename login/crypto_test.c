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

#include <glib.h>
#include <glome.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "login.h"

static void test_derive(void) {
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t expected_public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  decode_hex(
      private_key, sizeof private_key,
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  decode_hex(
      expected_public_key, sizeof expected_public_key,
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  g_assert_true(derive_or_generate_key(private_key, public_key) == 0);
  g_assert_cmpmem(expected_public_key, sizeof expected_public_key, public_key,
                  sizeof public_key);
}

static void test_generate(void) {
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t empty_public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t empty_private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  g_assert_true(derive_or_generate_key(private_key, public_key) == 0);
  g_assert_true(memcmp(empty_public_key, public_key, sizeof empty_public_key));
  g_assert_true(
      memcmp(empty_private_key, private_key, sizeof empty_private_key));
}

static void test_authcode(void) {
  const char* host_id = "myhost";
  const char* action = "exec=/bin/sh";

  uint8_t service_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  decode_hex(
      private_key, sizeof private_key,
      "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead");
  decode_hex(
      service_key, sizeof service_key,
      "d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647");

  uint8_t authcode[GLOME_MAX_TAG_LENGTH];
  uint8_t expected_authcode[GLOME_MAX_TAG_LENGTH];
  decode_hex(
      expected_authcode, sizeof expected_authcode,
      "666c5cccde31de0e20a17bbe03602eb841157ed812eb133eea0623f9d46b962b");

  char* message = glome_login_message(/*host_id_type=*/NULL, host_id, action);
  g_assert_nonnull(message);
  g_assert(glome_tag(true, 0, private_key, service_key, (uint8_t*)message,
                     strlen(message), authcode) == 0);
  g_assert_cmpmem(expected_authcode, sizeof expected_authcode, authcode,
                  sizeof authcode);
}

int main(int argc, char** argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/test-derive", test_derive);
  g_test_add_func("/test-generate", test_generate);
  g_test_add_func("/test-authcode", test_authcode);

  return g_test_run();
}
