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

#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

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

  char *v = p;
  for (; !isspace(*p) && *p != '\0'; p++) {
  }
  if (*p != '\0') {
    *p = '\0';
    for (p++; isspace(*p); p++) {
    }
  }
  if (*p != '\0') {
    return;
  }

  *key = line;
  *val = v;
}

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

  FILE *f = fopen(config->config_path, "r");
  if (f == NULL) {
    if (!required) {
      return 0;
    }
    errorf("ERROR: config file could not be opened: %s\n", strerror(errno));
    return -1;
  }

  char *section = NULL;
  char *key, *val;
  char *line = NULL;
  size_t len = 0;
  size_t lines = 0;
  int rc = -2;
  while (getline(&line, &len, f) != -1) {
    lines++;
    if (is_empty(line) || is_comment(line)) {
      continue;
    } else if (is_section(line)) {
      char *s = section_name(line);
      if (s == NULL) {
        errorf(
            "ERROR: config file parsing failed in line %ld (bad section "
            "name)\n",
            lines);
        goto out;
      }
      free(section);
      section = strdup(s);
    } else {
      key_value(line, &key, &val);
      if (key == NULL || val == NULL) {
        errorf(
            "ERROR: config file parsing failed in line %ld (bad key/value)\n",
            lines);
        goto out;
      }
      if (!assign(config, section, key, val)) {
        errorf(
            "ERROR: config file parsing failed in line %ld (bad assignment)\n",
            lines);
        goto out;
      }
    }
  }
  rc = 0;

out:
  free(line);
  free(section);
  fclose(f);
  return rc;
}
