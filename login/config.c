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

#include "config.h"

#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "base64.h"
#include "ui.h"

static bool is_empty(const char *line) {
  for (; isspace(*line); line++) {
  }
  return *line == '\0';
}

static bool is_comment(const char *line) {
  return line[0] == '#' || line[0] == ';';
}

static bool is_section(const char *line) { return line[0] == '['; }

static bool is_name(const char *name) {
  const char *p;
  for (p = name; isalnum(*p) || *p == '_' || *p == '-'; p++) {
  }
  return *p == '\0' && p - name > 0;
}

static char *section_name(char *line) {
  char *p;
  for (p = line + 1; *p != ']' && *p != '\0'; p++) {
  }
  if (*p != ']') {
    return NULL;
  }
  char *end = p;
  if (!is_empty(p + 1)) {
    return NULL;
  }
  *end = '\0';
  if (is_name(line + 1)) {
    return line + 1;
  }
  return NULL;
}

static void key_value(char *line, char **key, char **val) {
  *key = NULL;
  *val = NULL;

  char *p;
  for (p = line; !isspace(*p) && *p != '=' && *p != '\0'; p++) {
  }
  if (*p == '\0') {
    return;
  }
  char *end = p;

  for (; isspace(*p); p++) {
  }
  if (*p != '=') {
    return;
  }
  for (p++; isspace(*p); p++) {
  }
  if (*p == '\0') {
    return;
  }

  *end = '\0';
  if (!is_name(line)) {
    return;
  }

  // Trim whitespace at the end of the value.
  int k = strlen(p) - 1;
  for (; k >= 0 && isspace(p[k]); k--) {
  }
  p[k + 1] = '\0';

  *key = line;
  *val = p;
}

bool glome_login_parse_public_key(const char *encoded_key, uint8_t *public_key,
                                  size_t public_key_size) {
  if (public_key_size < GLOME_MAX_PUBLIC_KEY_LENGTH) {
    errorf("ERROR: provided buffer has size %zu, need at least %d\n",
           public_key_size, GLOME_MAX_PUBLIC_KEY_LENGTH);
    return false;
  }
  size_t prefix_length = strlen(GLOME_LOGIN_PUBLIC_KEY_ID);
  if (strncmp(encoded_key, GLOME_LOGIN_PUBLIC_KEY_ID, prefix_length)) {
    errorf("ERROR: unsupported public key encoding: %s\n", encoded_key);
    return false;
  }

  // Advance to the start of the base64-encoded key.
  encoded_key += prefix_length;
  while (*encoded_key != '\0' && isblank(*encoded_key)) {
    encoded_key++;
  }
  // Truncate the encoded string to allow for appended comments.
  size_t encoded_length = 0;
  while (isgraph(encoded_key[encoded_length])) {
    encoded_length++;
  }

  // Unfortunately we need an extra byte because 32B don't pack cleanly in
  // base64.
  uint8_t buf[GLOME_MAX_PUBLIC_KEY_LENGTH + 1] = {0};
  size_t b = base64url_decode((uint8_t *)encoded_key, encoded_length, buf,
                              sizeof(buf));
  if (b != GLOME_MAX_PUBLIC_KEY_LENGTH) {
    errorf("ERROR: public key decoded to %zu bytes, expected %d\n", b,
           GLOME_MAX_PUBLIC_KEY_LENGTH);
    return false;
  }

  memcpy(public_key, buf, GLOME_MAX_PUBLIC_KEY_LENGTH);
  return true;
}

static status_t assign_string_option(const char **option, const char *val) {
  const char *copy = strdup(val);
  if (copy == NULL) {
    return status_createf("ERROR: failed to allocate memory for value: %s",
                          val);
  }

  *option = copy;
  return STATUS_OK;
}

static status_t assign_positive_int_option(unsigned int *option,
                                           const char *val) {
  char *end;
  errno = 0;
  unsigned long n = strtoul(val, &end, 0);  // NOLINT(runtime/int)
  if (errno || val == end || *end != '\0' || n > UINT_MAX) {
    return status_createf("ERROR: invalid value for option: %s", val);
  }
  *option = (unsigned int)n;
  return STATUS_OK;
}

static status_t set_bitfield_option(glome_login_config_t *config, uint8_t bit) {
  config->options |= bit;
  return STATUS_OK;
}

static status_t clear_bitfield_option(glome_login_config_t *config,
                                      uint8_t bit) {
  config->options &= ~bit;
  return STATUS_OK;
}

static bool boolean_true(const char *val) {
  if (strcasecmp(val, "true") == 0) {
    return true;
  } else if (strcasecmp(val, "yes") == 0) {
    return true;
  } else if (strcasecmp(val, "on") == 0) {
    return true;
  } else if (strcmp(val, "1") == 0) {
    return true;
  }
  return false;
}

static bool boolean_false(const char *val) {
  if (strcasecmp(val, "false") == 0) {
    return true;
  } else if (strcasecmp(val, "no") == 0) {
    return true;
  } else if (strcasecmp(val, "off") == 0) {
    return true;
  } else if (strcmp(val, "0") == 0) {
    return true;
  }
  return false;
}

static status_t update_bitfield_option(glome_login_config_t *config,
                                       uint8_t bit, bool invert,
                                       const char *val) {
  if (boolean_true(val)) {
    if (invert) {
      return clear_bitfield_option(config, bit);
    } else {
      return set_bitfield_option(config, bit);
    }
  } else if (boolean_false(val)) {
    if (invert) {
      return set_bitfield_option(config, bit);
    } else {
      return clear_bitfield_option(config, bit);
    }
  } else {
    return status_createf("ERROR: unrecognized boolean value: %s", val);
  }
}

static status_t assign_key_option(uint8_t *dest, size_t dest_len,
                                  const char *val) {
  if (is_zeroed(dest, dest_len)) {
    if (decode_hex(dest, dest_len, val)) {
      return status_createf("ERROR: failed to hex decode service key: %s", val);
    }
  }
  return STATUS_OK;
}

static status_t assign_key_version_option(glome_login_config_t *config,
                                          const char *val) {
  char *end;
  errno = 0;
  unsigned long n = strtoul(val, &end, 0);  // NOLINT(runtime/int)
  if (errno || val == end || *end != '\0' || n > 127) {
    return status_createf("ERROR: '%s' is not a valid key version (0..127)",
                          val);
  }
  config->service_key_id = (unsigned int)n;
  return STATUS_OK;
}

static status_t assign_default_option(glome_login_config_t *config,
                                      const char *key, const char *val) {
  if (strcmp(key, "auth-delay") == 0) {
    return assign_positive_int_option(&config->auth_delay_sec, val);
  } else if (strcmp(key, "input-timeout") == 0) {
    return assign_positive_int_option(&config->input_timeout_sec, val);
  } else if (strcmp(key, "config-path") == 0) {
    return assign_string_option(&config->config_path, val);
  } else if (strcmp(key, "ephemeral-key") == 0) {
    return assign_key_option(config->secret_key, sizeof config->secret_key,
                             val);
  } else if (strcmp(key, "min-authcode-len") == 0) {
    return assign_positive_int_option(&config->min_authcode_len, val);
  } else if (strcmp(key, "host-id") == 0) {
    return assign_string_option(&config->host_id, val);
  } else if (strcmp(key, "login-path") == 0) {
    return assign_string_option(&config->login_path, val);
  } else if (strcmp(key, "disable-syslog") == 0) {
    return update_bitfield_option(config, SYSLOG, true, val);
  } else if (strcmp(key, "print-secrets") == 0) {
    return update_bitfield_option(config, INSECURE, false, val);
  } else if (strcmp(key, "timeout") == 0) {
    return assign_positive_int_option(&config->input_timeout_sec, val);
  } else if (strcmp(key, "verbose") == 0) {
    return update_bitfield_option(config, VERBOSE, false, val);
  }

  return status_createf("ERROR: unrecognized default option: %s", key);
}

static status_t assign_service_option(glome_login_config_t *config,
                                      const char *key, const char *val) {
  if (strcmp(key, "key") == 0) {
    return assign_key_option(config->service_key, sizeof config->service_key,
                             val);
  } else if (strcmp(key, "key-version") == 0) {
    return assign_key_version_option(config, val);
  } else if (strcmp(key, "url-prefix") == 0) {
    // `url-prefix` support is provided only for backwards-compatiblity
    // TODO: to be removed in the 1.0 release
    size_t len = strlen(val);
    char *url_prefix = malloc(len + 2);
    if (url_prefix == NULL) {
      return status_createf("ERROR: failed to allocate memory for url_prefix");
    }
    strncpy(url_prefix, val, len + 1);
    url_prefix[len] = '/';
    url_prefix[len + 1] = '\0';
    config->prompt = url_prefix;
    return STATUS_OK;
  } else if (strcmp(key, "prompt") == 0) {
    return assign_string_option(&config->prompt, val);
  } else if (strcmp(key, "public-key") == 0) {
    if (!glome_login_parse_public_key(val, config->service_key,
                                      sizeof(config->service_key))) {
      return status_createf("ERROR: failed to decode public-key");
    }
    return STATUS_OK;
  }

  return status_createf("ERROR: unrecognized service option: %s", key);
}

status_t glome_login_assign_config_option(glome_login_config_t *config,
                                          const char *section, const char *key,
                                          const char *val) {
  if (section == NULL) {
    return status_createf("ERROR: section name not set");
  }

  if (strcmp(section, "service") == 0) {
    return assign_service_option(config, key, val);
  } else if (strcmp(section, "default") == 0) {
    return assign_default_option(config, key, val);
  }

  return status_createf("ERROR: section name not recognized: %s", section);
}

status_t glome_login_parse_config_file(glome_login_config_t *config) {
  bool required = config->config_path != NULL;
  if (!required) {
    config->config_path = DEFAULT_CONFIG_FILE;
  }

  FILE *f = fopen(config->config_path, "r");
  if (f == NULL) {
    if (!required) {
      return 0;
    }
    return status_createf("ERROR: config file could not be opened: %s\n",
                          strerror(errno));
  }

  char *line = NULL;
  char *section = NULL;
  char *key, *val;
  size_t len = 0;
  size_t lines = 0;
  status_t status = STATUS_OK;
  while (getline(&line, &len, f) != -1) {
    lines++;
    if (is_empty(line) || is_comment(line)) {
      continue;
    } else if (is_section(line)) {
      char *s = section_name(line);
      if (s == NULL) {
        status = status_createf(
            "ERROR: config file parsing failed in line %ld (bad section "
            "name)\n",
            lines);
        break;
      }
      free(section);
      section = strdup(s);
    } else {
      key_value(line, &key, &val);
      if (key == NULL || val == NULL) {
        status = status_createf(
            "ERROR: config file parsing failed in line %ld (bad key/value)\n",
            lines);
        break;
      }
      status = glome_login_assign_config_option(
          config, section ? section : "default", key, val);
      if (status != STATUS_OK) {
        break;
      }
    }
  }

  free(line);
  free(section);
  fclose(f);
  return status;
}
