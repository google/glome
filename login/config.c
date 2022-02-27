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
#include <openssl/conf.h>
#include <string.h>

#include "ui.h"

static bool assign(glome_login_config_t *config, const char *section,
                   const char *key, const char *val) {
  if (section == NULL || strcmp(section, "service") != 0) {
    return true;
  }

  if (strcmp(key, "key") == 0) {
    if (is_zeroed(config->service_key, sizeof config->service_key)) {
      if (decode_hex(config->service_key, sizeof config->service_key, val)) {
        errorf("ERROR: Failed to hex decode service key\n");
        return false;
      }
    }
  } else if (strcmp(key, "key-version") == 0) {
    char *end;
    errno = 0;
    long n = strtol(val, &end, 10);
    if (errno != 0 || *end != '\0') {
      errorf("ERROR: Failed to parse service key version\n");
      return false;
    }
    if (n <= 0) {
      errorf("ERROR: Key version should be a positive value\n");
      return false;
    }
    if (n > 255) {
      errorf("ERROR: Key version too large, must fit into 8-bit int\n");
      return false;
    }
    if (n > 0 && config->service_key_id == 0) {
      config->service_key_id = n;
    }
  } else if (strcmp(key, "url-prefix") == 0) {
    if (config->url_prefix == NULL) {
      config->url_prefix = strdup(val);
    }
  }

  return true;
}

int glome_login_parse_config_file(glome_login_config_t *config) {
  bool required = config->config_path != NULL;
  if (!required) {
    config->config_path = DEFAULT_CONFIG_FILE;
  }

  int rc = -1;
  CONF *conf = NULL;
  if ((conf = NCONF_new(NULL)) == NULL) {
    errorf("ERROR: config file could not be initialized\n");
    goto out;
  }

  long errline = -1;
  if (NCONF_load(conf, config->config_path, &errline) <= 0) {
    if (errline <= 0) {
      if (required) {
        errorf("ERROR: config file could not be read\n");
      } else {
        rc = 0;
      }
    } else {
      errorf("ERROR: config file could not be parsed (line %ld)\n", errline);
    }
    goto out;
  }

  STACK_OF(CONF_VALUE) *sect = NCONF_get_section(conf, "service");
  if (sect == NULL) {
    rc = 0;
    goto out;
  }

  for (int i = 0; i < sk_CONF_VALUE_num(sect); i++) {
    CONF_VALUE *v = sk_CONF_VALUE_value(sect, i);
    if (!assign(config, v->section, v->name, v->value)) {
      rc = -2;
      goto out;
    }
  }
  rc = 0;

out:
  NCONF_free(conf);
  return rc;
}
