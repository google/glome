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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Needs to go last to get size_t definition. */
#include <libpamtest.h>

const char *authtoks[] = {
    "lyHuaHuCck",  /* Correct code */
    "lyHuaHuCc",   /* Too short */
    "INVALIDCODE", /* Wrong code */
    /* fake passwords that might be provided by openssh-portable/auth-pam.c */
    "\b\n\r\177", "\b\n\r\177INCORRECT", "\b\n\r\177INCORRECT\b\n\r\177",
    NULL /* Terminator */
};

struct pamtest_conv_data conv_data = {
    .in_echo_off = authtoks,
};

struct pam_testcase tests[] = {
    pam_test(PAMTEST_AUTHENTICATE, PAM_SUCCESS),
    pam_test(PAMTEST_AUTHENTICATE, PAM_AUTH_ERR),
    pam_test(PAMTEST_AUTHENTICATE, PAM_AUTH_ERR),
    pam_test(PAMTEST_AUTHENTICATE, PAM_AUTH_ERR),
    pam_test(PAMTEST_AUTHENTICATE, PAM_AUTH_ERR),
    pam_test(PAMTEST_AUTHENTICATE, PAM_AUTH_ERR),
};

/* Setup GLOME using only PAM parameters. */
int test_service() {
  int len;
  enum pamtest_err perr;
  char *runtime_dir, *pam_glome, *service_file;
  char *service = "test";
  char *username = "root";
  FILE *f;

  pam_glome = getenv("PAM_GLOME");
  if (pam_glome == NULL) {
    puts("PAM_GLOME not found");
    return 1;
  }

  runtime_dir = getenv("PAM_WRAPPER_RUNTIME_DIR");
  if (runtime_dir == NULL) {
    puts("PAM_WRAPPER_RUNTIME_DIR not found");
    return 1;
  }

  len = strlen(runtime_dir) + 1 + strlen(service) + 1;
  service_file = calloc(len, 1);
  if (service_file == NULL) {
    puts("calloc service_file failed");
    return 1;
  }

  snprintf(service_file, len, "%s/%s", runtime_dir, service);
  f = fopen(service_file, "w");
  if (f == NULL) {
    printf("fopen service_file '%s' failed: %s\n", service_file,
           strerror(errno));
    return 1;
  }
  free(service_file);

  fprintf(f,
          "auth required %s url_prefix=https://test.service "
          "key="
          "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f "
          "key_version=1 "
          "ephemeral_key="
          "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a "
          "host_id=my-server.local",
          pam_glome);
  fclose(f);

#if defined(OLDSTYLE_RUN_PAMTEST)
  perr = run_pamtest(service, username, &conv_data, tests);
#else
  perr = run_pamtest(service, username, &conv_data, tests, NULL);
#endif
  if (perr != PAMTEST_ERR_OK) {
    puts(pamtest_strerror(perr));
    return 1;
  }

  return 0;
}

/* Setup GLOME using config file and PAM parameters. */
int test_config() {
  int len;
  enum pamtest_err perr;
  char *runtime_dir, *pam_glome, *service_file, *config_file;
  char *service = "test";
  char *config = "config";
  char *username = "root";
  FILE *f;

  pam_glome = getenv("PAM_GLOME");
  if (pam_glome == NULL) {
    puts("PAM_GLOME not found");
    return 1;
  }

  runtime_dir = getenv("PAM_WRAPPER_RUNTIME_DIR");
  if (runtime_dir == NULL) {
    puts("PAM_WRAPPER_RUNTIME_DIR not found");
    return 1;
  }

  len = strlen(runtime_dir) + 1 + strlen(config) + 1;
  config_file = calloc(len, 1);
  if (config_file == NULL) {
    puts("calloc config_file failed");
    return 1;
  }
  snprintf(config_file, len, "%s/%s", runtime_dir, config);

  f = fopen(config_file, "w");
  if (f == NULL) {
    printf("fopen config_file '%s' failed: %s\n", config_file, strerror(errno));
    return 1;
  }

  fprintf(f,
          "[service]\n"
          "key = "
          "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f\n"
          "key-version = 1\n"
          "url-prefix = https://test.service\n");
  fclose(f);

  len = strlen(runtime_dir) + 1 + strlen(service) + 1;
  service_file = calloc(len, 1);
  if (service_file == NULL) {
    puts("calloc service_file failed");
    return 1;
  }

  snprintf(service_file, len, "%s/%s", runtime_dir, service);
  f = fopen(service_file, "w");
  if (f == NULL) {
    printf("fopen service_file '%s' failed: %s\n", service_file,
           strerror(errno));
    return 1;
  }
  free(service_file);

  fprintf(f,
          "auth required %s config_path=%s "
          "ephemeral-key="
          "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a "
          "host-id=my-server.local",
          pam_glome, config_file);
  fclose(f);
  free(config_file);

#if defined(OLDSTYLE_RUN_PAMTEST)
  perr = run_pamtest(service, username, &conv_data, tests);
#else
  perr = run_pamtest(service, username, &conv_data, tests, NULL);
#endif

  if (perr != PAMTEST_ERR_OK) {
    puts(pamtest_strerror(perr));
    return 1;
  }

  return 0;
}

int main() {
  int rc;

  rc = test_service();
  rc = rc || test_config();

  return rc;
}
