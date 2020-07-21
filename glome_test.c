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

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void decode_hex(uint8_t* dst, const char* in) {
  size_t len = strlen(in);
  size_t i;
  for (i = 0; i < len / 2; i++) {
    sscanf(in + (i * 2), "%02hhX", dst + i);
  }
}

START_TEST(test_vector_1) {
  uint8_t ka_priv[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t ka_pub[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t kb_pub[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t expected_tag[GLOME_MAX_TAG_LENGTH] = {0};
  uint8_t tag[GLOME_MAX_TAG_LENGTH] = {0};
  uint8_t counter = 0;
  const char *msg = "The quick brown fox";

  decode_hex(
      ka_priv,
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  decode_hex(
      kb_pub,
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  decode_hex(
      expected_tag,
      "9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3");

  ck_assert_int_eq(glome_derive_key(ka_priv, ka_pub), 0);
  ck_assert_int_eq(glome_tag(/* verify */ false, counter, ka_priv, ka_pub, kb_pub,
        (const uint8_t*)msg, strlen(msg), tag), 0);

  /* only with check >= 0.11:
   * ck_assert_mem_eq(tag, expected_tag, sizeof expected_tag);
   */
  ck_assert_int_eq(memcmp(tag, expected_tag, sizeof expected_tag), 0);
}
END_TEST

START_TEST(test_vector_2) {
  uint8_t ka_pub[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t kb_priv[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t kb_pub[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t expected_tag[GLOME_MAX_TAG_LENGTH] = {0};
  uint8_t tag[GLOME_MAX_TAG_LENGTH] = {0};
  uint8_t counter = 100;
  const char *msg = "The quick brown fox";

  decode_hex(
      ka_pub,
      "872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376");
  decode_hex(
      kb_priv,
      "b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d");
  decode_hex(
      expected_tag,
      "06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277");

  ck_assert_int_eq(glome_derive_key(kb_priv, kb_pub), 0);
  ck_assert_int_eq(glome_tag(/* verify */ false, counter, kb_priv, kb_pub, ka_pub,
        (const uint8_t*)msg, strlen(msg), tag), 0);

  /* only with check >= 0.11:
   * ck_assert_mem_eq(tag, expected_tag, sizeof expected_tag);
   */
  ck_assert_int_eq(memcmp(tag, expected_tag, sizeof expected_tag), 0);
}
END_TEST

int main (int argc, char *argv[]) {
  Suite* s = suite_create("protocol-spec");
  TCase* tc = tcase_create("test-vectors");

  tcase_add_test(tc, test_vector_1);
  tcase_add_test(tc, test_vector_2);
  suite_add_tcase(s, tc);

  SRunner* sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  int number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
