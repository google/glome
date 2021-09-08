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
#include <iniparser/iniparser.h>
#include <string.h>

#include "ui.h"

static void dict_free(dictionary **dict)
{
  iniparser_freedict(*dict);
}

int glome_login_parse_config_file(glome_login_config_t* config) {
  dictionary *dict __attribute__((__cleanup__(dict_free))) = NULL;

  bool required = config->config_path != NULL;
  if (!required) {
    config->config_path = DEFAULT_CONFIG_FILE;
  }

  dict = iniparser_load(config->config_path);
  if (dict == NULL) {
    if (required) {
      errorf("ERROR: config file could not be read\n");
      return -1;
    }
    return 0;
  }

  const char *service_key = iniparser_getstring(dict, "service:key", NULL);
  if (service_key != NULL &&
      is_zeroed(config->service_key, sizeof config->service_key)) {
    if (decode_hex(config->service_key, sizeof config->service_key,
                   service_key)) {
      errorf("ERROR: Failed to hex decode service key\n");
      return -2;
    }
  }

  int service_key_version =
      iniparser_getint(dict, "service:key-version", -1);
  if (service_key_version & ~0xff) {
    errorf("ERROR: Key version %d too large, must fit into 8-bit uint\n",
           service_key_version);
    return -3;
  }
  if (service_key_version > 0 && config->service_key_id == 0) {
    config->service_key_id = service_key_version;
  }

  const char *url_prefix = iniparser_getstring(dict, "service:url-prefix", NULL);
  if (url_prefix != NULL && config->url_prefix == NULL) {
    config->url_prefix = strdup(url_prefix);
  }

  return 0;
}
