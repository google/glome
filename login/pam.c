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

static int parse_pam_args(pam_handle_t *pamh, int argc, const char **argv,
                          login_config_t *config) {
  memset(config, 0, sizeof(login_config_t));
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

static int get_username(pam_handle_t *pamh, login_config_t *config,
                        const char **error_tag) {
  const char *username;
  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username ||
      !*username) {
    return failure(EXITCODE_PANIC, error_tag, "get-username");
  }
  config->username = username;
  return 0;
}

static int glome_authenticate(pam_handle_t *pamh, login_config_t *config,
                              const char **error_tag, int argc,
                              const char **argv) {
  if (is_zeroed(config->service_key, sizeof config->service_key)) {
    return failure(EXITCODE_PANIC, error_tag, "no-service-key");
  }

  uint8_t public_key[PUBLIC_KEY_LENGTH] = {0};
  if (derive_or_generate_key(config->secret_key, public_key)) {
    return failure(EXITCODE_PANIC, error_tag, "derive-or-generate-key");
  }

  char *host_id = NULL;
  if (config->host_id != NULL) {
    host_id = strdup(config->host_id);
  } else {
    host_id = calloc(HOST_NAME_MAX + 1, 1);
    if (get_machine_id(host_id, HOST_NAME_MAX + 1, error_tag) < 0) {
      return failure(EXITCODE_PANIC, error_tag, "get-machine-id");
    }
  }

  char *action = NULL;
  size_t action_len = 0;

  if (shell_action(config->username, &action, &action_len, error_tag)) {
    free(host_id);
    return EXITCODE_PANIC;
  }

  if (config->options & VERBOSE) {
    pam_syslog(pamh, LOG_DEBUG, "host ID: %s", host_id);
    pam_syslog(pamh, LOG_DEBUG, "action: %s", action);
  }

  uint8_t authcode[GLOME_MAX_TAG_LENGTH];
  if (get_authcode(host_id, action, config->service_key, config->secret_key,
                   authcode)) {
    free(host_id);
    free(action);
    return failure(EXITCODE_PANIC, error_tag, "get-authcode");
  }

  char *url = NULL;
  int url_len = 0;
  if (request_url(config->service_key, config->service_key_id, public_key,
                  host_id, action, /*prefix_tag=*/NULL,
                  /*prefix_tag_len=*/0, &url, &url_len, error_tag)) {
    free(host_id);
    free(action);
    return EXITCODE_PANIC;
  }

  free(host_id);
  host_id = NULL;
  free(action);
  action = NULL;

  struct pam_conv *conv;
  if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) {
    return failure(EXITCODE_PANIC, error_tag, "pam-get-conv");
  }

  const char *template = "GLOME link: %s%s";
  size_t message_len =
      strlen(template) + strlen(config->url_prefix) + strlen(url) - 4 + 1;
  char *message = malloc(message_len);
  if (message == NULL) {
    return failure(EXITCODE_PANIC, error_tag, "malloc-message");
  }
  int written =
      snprintf(message, message_len, template, config->url_prefix, url);
  if (written < 0 || written >= message_len) {
    return failure(EXITCODE_PANIC, error_tag, "broken-template");
  }
  free(url);
  url = NULL;

  struct pam_message msg[1] = {
      {.msg = message, .msg_style = PAM_TEXT_INFO},
  };
  const struct pam_message *pmsg[1] = {&msg[0]};
  struct pam_response *resp = NULL;
  if (conv->conv(1, pmsg, &resp, conv->appdata_ptr) != PAM_SUCCESS) {
    free(message);
    return failure(EXITCODE_PANIC, error_tag, "pam-conv");
  }
  free(message);

  const char *input = NULL;
  if (pam_get_authtok(pamh, PAM_AUTHTOK, &input, NULL) != PAM_SUCCESS) {
    return failure(EXITCODE_PANIC, error_tag, "pam-get-authtok");
  }

  int bytes_read = strlen(input);
  if (config->options & INSECURE) {
    pam_syslog(pamh, LOG_DEBUG, "user input: %s", input);
  }

  // Calculate the correct authcode.
  char authcode_encoded[ENCODED_BUFSIZE(sizeof authcode)] = {0};
  if (base64url_encode(authcode, sizeof authcode, (uint8_t *)authcode_encoded,
                       sizeof authcode_encoded) == 0) {
    return failure(EXITCODE_PANIC, error_tag, "authcode-encode");
  }
  if (config->options & INSECURE) {
    pam_syslog(pamh, LOG_DEBUG, "expect input: %s", authcode_encoded);
  }

  if (bytes_read < MIN_ENCODED_AUTHCODE_LEN) {
    return failure(EXITCODE_INVALID_INPUT_SIZE, error_tag, "authcode-length");
  }
  if (bytes_read > strlen(authcode_encoded)) {
    return failure(EXITCODE_INVALID_INPUT_SIZE, error_tag, "authcode-length");
  }

  if (CRYPTO_memcmp(input, authcode_encoded, bytes_read) != 0) {
    return failure(EXITCODE_INVALID_AUTHCODE, error_tag, "authcode-invalid");
  }

  return 0;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  const char *error_tag = NULL;
  login_config_t config = {0};
  int rc = PAM_AUTH_ERR;

  int r = parse_pam_args(pamh, argc, argv, &config);
  if (r < 0) {
    pam_syslog(pamh, LOG_ERR, "failed to parse pam module arguments (%d)", r);
    return rc;
  }

  r = parse_config_file(&config);
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

  r = glome_authenticate(pamh, &config, &error_tag, argc, argv);
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
  return PAM_SUCCESS;
}
