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
#include <limits.h>
#include <openssl/crypto.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "base64.h"
#include "config.h"
#include "login.h"
#include "ui.h"

#define MODULE_NAME "pam_glome"

#define MAX_ERROR_MESSAGE_SIZE 4095

#define UNUSED(var) (void)(var)

static int parse_pam_args(pam_handle_t *pamh, int argc, const char **argv,
                          glome_login_config_t *config) {
  memset(config, 0, sizeof(glome_login_config_t));
  int errors = 0;

  for (int i = 0; i < argc; ++i) {
    if (!strncmp(argv[i], "config_path=", 12)) {
      config->config_path = argv[i] + 12;
    } else if (!strncmp(argv[i], "service_key=", 12)) {
      if (decode_hex(config->service_key, sizeof config->service_key,
                     argv[i] + 12) != 0) {
        pam_syslog(pamh, LOG_ERR, "invalid value for %s", argv[i]);
        errors++;
      }
    } else if (!strncmp(argv[i], "service_key_version=", 20)) {
      char *endptr;
      long l;
      errno = 0;
      l = strtol(argv[i] + 20, &endptr, 0);
      if (errno) {
        pam_syslog(pamh, LOG_ERR, "invalid value for %s", argv[i]);
        errors++;
        continue;
      }
      if (*endptr != '\0' || l <= 0 || l > UINT8_MAX) {
        pam_syslog(pamh, LOG_ERR, "invalid value for %s", argv[i]);
        errors++;
        continue;
      }
      config->service_key_id = (uint8_t)l;
    } else if (!strncmp(argv[i], "url_prefix=", 11)) {
      config->url_prefix = argv[i] + 11;
    } else if (!strcmp(argv[i], "debug")) {
      config->options |= VERBOSE;
    } else if (!strcmp(argv[i], "insecure_debug")) {
      config->options |= INSECURE;
    } else if (!strncmp(argv[i], "insecure_host_id=", 17)) {
      config->host_id = argv[i] + 17;
    } else if (!strncmp(argv[i], "insecure_secret_key=", 20)) {
      if (decode_hex(config->secret_key, sizeof config->secret_key,
                     argv[i] + 20) != 0) {
        pam_syslog(pamh, LOG_ERR, "invalid value for %s", argv[i]);
        errors++;
      }
    } else {
      pam_syslog(pamh, LOG_ERR, "invalid option %s", argv[i]);
      errors++;
    }
  }

  return errors > 0 ? -1 : 0;
}

static int get_username(pam_handle_t *pamh, glome_login_config_t *config,
                        const char **error_tag) {
  const char *username;
  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username ||
      !*username) {
    return failure(EXITCODE_PANIC, error_tag, "get-username");
  }
  config->username = username;
  return 0;
}

void login_error(glome_login_config_t *config, pam_handle_t *pamh,
                 const char *format, ...) {
  UNUSED(config);

  char message[MAX_ERROR_MESSAGE_SIZE] = {0};
  va_list argptr;
  va_start(argptr, format);
  int ret = vsnprintf(message, sizeof(message), format, argptr);
  va_end(argptr);
  if (ret < 0 || ret >= MAX_ERROR_MESSAGE_SIZE) {
    return;
  }

  struct pam_message msg[1] = {
      {.msg = message, .msg_style = PAM_ERROR_MSG},
  };
  const struct pam_message *pmsg[1] = {&msg[0]};
  struct pam_response *resp = NULL;
  struct pam_conv *conv;
  if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) {
    return;
  }
  if (conv->conv(1, pmsg, &resp, conv->appdata_ptr) != PAM_SUCCESS) {
    return;
  }
  if (resp != NULL) {
    free(resp->resp);
    free(resp);
  }
}

void login_syslog(glome_login_config_t *config, pam_handle_t *pamh,
                  int priority, const char *format, ...) {
  UNUSED(config);
  va_list argptr;
  va_start(argptr, format);
  pam_vsyslog(pamh, priority, format, argptr);
  va_end(argptr);
}

int login_prompt(glome_login_config_t *config, pam_handle_t *pamh,
                 const char **error_tag, const char *message, char *input,
                 size_t input_size) {
  UNUSED(config);
  struct pam_message msg[1] = {
      {.msg = message, .msg_style = PAM_TEXT_INFO},
  };
  const struct pam_message *pmsg[1] = {&msg[0]};
  struct pam_response *resp = NULL;
  struct pam_conv *conv;
  if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) {
    return failure(EXITCODE_PANIC, error_tag, "pam-get-conv");
  }
  if (conv->conv(1, pmsg, &resp, conv->appdata_ptr) != PAM_SUCCESS) {
    return failure(EXITCODE_PANIC, error_tag, "pam-conv");
  }
  if (resp != NULL) {
    free(resp->resp);
    free(resp);
  }
  const char *token;
  if (pam_get_authtok(pamh, PAM_AUTHTOK, &token, NULL) != PAM_SUCCESS) {
    return failure(EXITCODE_PANIC, error_tag, "pam-get-authtok");
  }
  if (strlen(token) >= input_size) {
    return failure(EXITCODE_PANIC, error_tag, "pam-authtok-size");
  }

  // OpenSSH provides fake password when login is not allowed,
  // for example due to PermitRootLogin set to 'no'
  // https://github.com/openssh/openssh-portable/commit/283b97
  const char fake_password[] =
      "\b\n\r\177INCORRECT";  // auth-pam.c from OpenSSH
  bool is_fake = true;

  // Constant-time comparison in case token contains user's password
  for (size_t i = 0; i < strlen(token); i++) {
    is_fake &= (token[i] == fake_password[i % (sizeof(fake_password) - 1)]);
  }
  if (is_fake) {
    return failure(EXITCODE_PANIC, error_tag, "pam-authtok-openssh-no-login");
  }

  strncpy(input, token, input_size);
  return 0;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  UNUSED(flags);

  const char *error_tag = NULL;
  glome_login_config_t config = {0};
  int rc = PAM_AUTH_ERR;

  int r = parse_pam_args(pamh, argc, argv, &config);
  if (r < 0) {
    pam_syslog(pamh, LOG_ERR, "failed to parse pam module arguments (%d)", r);
    return rc;
  }

  r = glome_login_parse_config_file(&config);
  if (r < 0) {
    pam_syslog(pamh, LOG_ERR, "failed to read config file: %s (%d)",
               config.config_path, r);
    return rc;
  }

  r = get_username(pamh, &config, &error_tag);
  if (r < 0) {
    pam_syslog(pamh, LOG_ERR, "failed to get username: %s (%d)", error_tag, r);
    return rc;
  }

  r = login_authenticate(&config, pamh, "GLOME link: %s%s", &error_tag);
  if (!r) {
    rc = PAM_SUCCESS;
    if (config.options & VERBOSE) {
      pam_syslog(pamh, LOG_ERR, "authenticated user '%s'", config.username);
    }
  } else {
    pam_syslog(pamh, LOG_ERR, "failed to authenticate user '%s': %s (%d)",
               config.username, error_tag, r);
  }

  return rc;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  /* This module does not generate any user credentials, so just skip. */
  UNUSED(pamh);
  UNUSED(flags);
  UNUSED(argc);
  UNUSED(argv);
  return PAM_SUCCESS;
}
