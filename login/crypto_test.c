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

static void test_derive() {
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

static void test_generate() {
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t empty_public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t empty_private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  g_assert_true(derive_or_generate_key(private_key, public_key) == 0);
  g_assert_true(memcmp(empty_public_key, public_key, sizeof empty_public_key));
  g_assert_true(
      memcmp(empty_private_key, private_key, sizeof empty_private_key));
}

static void test_authcode() {
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
  g_assert_true(get_authcode(/*host_id_type=*/NULL, host_id, action,
                             service_key, private_key, authcode) == 0);
  g_assert_cmpmem(expected_authcode, sizeof expected_authcode, authcode,
                  sizeof authcode);
}

// TODO: does not use actual test vector
static void test_msg_tag() {
  const char* host_id = "serial-number:1234567890=ABCDFGH/#?";
  const char* action = "reboot";

  uint8_t service_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  decode_hex(
      private_key, sizeof private_key,
      "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead");
  decode_hex(
      service_key, sizeof service_key,
      "d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647");

  uint8_t msg_tag[GLOME_MAX_TAG_LENGTH];
  uint8_t expected_msg_tag[GLOME_MAX_TAG_LENGTH];
  decode_hex(
      expected_msg_tag, sizeof expected_msg_tag,
      "76036ab00ec676e453c8a110b6bf63767f2a225f11b0055b18c24554b67a47fd");
  g_assert_true(get_msg_tag(/*host_id_type=*/NULL, host_id, action, service_key,
                            private_key, msg_tag) == 0);
  g_assert_cmpmem(expected_msg_tag, sizeof expected_msg_tag, msg_tag,
                  sizeof msg_tag);
}

int main(int argc, char** argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/test-derive", test_derive);
  g_test_add_func("/test-generate", test_generate);
  g_test_add_func("/test-authcode", test_authcode);
  g_test_add_func("/test-msg-tag", test_msg_tag);

  return g_test_run();
}
