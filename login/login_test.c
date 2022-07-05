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

#include "login.h"

#include <glib.h>
#include <glome.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "crypto.h"

static void test_shell_action() {
  const char* error_tag = NULL;
  char* action = NULL;
  size_t action_len = 0;
  shell_action("operator", &action, &action_len, &error_tag);

  g_assert_cmpstr("shell/operator", ==, action);
  g_assert_true(strlen(action) + 1 == action_len);
  g_assert_null(error_tag);
}

static void test_vector_1() {
  const char* host_id = "my-server.local";
  const char* action = "shell/root";

  uint8_t service_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  decode_hex(
      private_key, sizeof private_key,
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  decode_hex(
      service_key, sizeof service_key,
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

  g_assert_true(derive_or_generate_key(private_key, public_key) == 0);

  {
    uint8_t authcode[GLOME_MAX_TAG_LENGTH];
    g_assert_true(
        get_authcode(host_id, action, service_key, private_key, authcode) == 0);
    char authcode_encoded[ENCODED_BUFSIZE(sizeof authcode)] = {0};
    g_assert_true(base64url_encode(authcode, sizeof authcode,
                                   (uint8_t*)authcode_encoded,
                                   sizeof authcode_encoded));
    g_assert_cmpmem("lyHuaHuCck", 10, authcode_encoded, 10);
  }

  {
    const char* error_tag = NULL;
    char* url = NULL;
    int url_len = 0;
    int service_key_id = 1;
    uint8_t prefix_tag[GLOME_MAX_TAG_LENGTH];

    g_assert_true(get_msg_tag(host_id, action, service_key, private_key,
                              prefix_tag) == 0);

    if (request_url(service_key, service_key_id, public_key, host_id, action,
                    prefix_tag, /*prefix_tag_len=*/2, &url, &url_len,
                    &error_tag)) {
      g_test_message("construct_request_url failed: %s", error_tag);
      g_test_fail();
    }

    g_assert_cmpstr(
        "v1/AYUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q0PU=/"
        "my-server.local/shell/root/",
        ==, url);
    g_assert_null(error_tag);
  }
}

static void test_vector_2() {
  const char* host_id = "serial-number:1234567890=ABCDFGH/#?";
  const char* action = "reboot";

  uint8_t service_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  decode_hex(
      private_key, sizeof private_key,
      "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead");
  decode_hex(
      service_key, sizeof service_key,
      "d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647");

  g_assert_true(derive_or_generate_key(private_key, public_key) == 0);

  {
    uint8_t authcode[GLOME_MAX_TAG_LENGTH];
    g_assert_true(
        get_authcode(host_id, action, service_key, private_key, authcode) == 0);
    char authcode_encoded[ENCODED_BUFSIZE(sizeof authcode)] = {0};
    g_assert_true(base64url_encode(authcode, sizeof authcode,
                                   (uint8_t*)authcode_encoded,
                                   sizeof authcode_encoded));
    g_assert_cmpstr("p8M_BUKj7zXBVM2JlQhNYFxs4J-DzxRAps83ZaNDquY=", ==,
                    authcode_encoded);
  }

  {
    const char* error_tag = NULL;
    char* url = NULL;
    int url_len = 0;
    int service_key_id = 0;
    if (request_url(service_key, service_key_id, public_key, host_id, action,
                    /*prefix_tag=*/NULL, /*prefix_tag_len=*/0, &url, &url_len,
                    &error_tag)) {
      g_test_message("construct_request_url failed: %s", error_tag);
      g_test_fail();
    }

    g_assert_cmpstr(
        "v1/UYcvQ1u4uJ0OOtYqouURB07hleHDnvaogAFBi-ZW48N2/"
        "serial-number:1234567890=ABCDFGH%2F%23%3F/reboot/",
        ==, url);
    g_assert_null(error_tag);
  }
}

int main(int argc, char** argv) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/test-shell-action", test_shell_action);
  g_test_add_func("/test-vector-1", test_vector_1);
  g_test_add_func("/test-vector-2", test_vector_2);

  return g_test_run();
}
