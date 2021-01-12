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
#include <confuse.h>
#include <string.h>

#include "ui.h"

static void print_config_error(cfg_t* cfg, const char* fmt, va_list ap) {
  char* format = alloca(7 + strlen(fmt) + 1);
  strcpy(format, "ERROR: ");
  strcat(format, fmt);
  errorf(format, ap);
}

int parse_config_file(login_config_t* config) {
  char* service_key = NULL;
  long service_key_version = 0;
  char* url_prefix = NULL;
  // clang-format off
  cfg_opt_t service_opts[] = {
      CFG_SIMPLE_STR("key", &service_key),  // Hex-encoded service key
      CFG_SIMPLE_INT("key-version", &service_key_version),  // Key version
      CFG_SIMPLE_STR("url-prefix", &url_prefix),  // HTTP URL prefix of web service
      CFG_END()
  };
  cfg_opt_t opts[] = {
    CFG_SEC("service", service_opts, CFGF_NONE),
    CFG_END()
  };
  // clang-format on
  cfg_t* cfg = cfg_init(opts, CFGF_NONE);
  cfg_set_error_function(cfg, print_config_error);

  int required = config->config_path != NULL;
  if (!required) {
    config->config_path = DEFAULT_CONFIG_FILE;
  }

  int r = cfg_parse(cfg, config->config_path);
  if (required && r == CFG_FILE_ERROR) {
    perror("ERROR: config file could not be read");
    cfg_free(cfg);
    return -1;
  } else if (r == CFG_PARSE_ERROR) {
    // print_config_error will have been invoked by cfg_parse to print the
    // error encountered.
    cfg_free(cfg);
    return -2;
  }

  cfg_t* cfg_service = cfg_getsec(cfg, "service");
  if (cfg_service != NULL) {
    if (service_key != NULL &&
        is_zeroed(config->service_key, sizeof config->service_key)) {
      if (decode_hex(config->service_key, sizeof config->service_key,
                     service_key)) {
        errorf("ERROR: Failed to hex decode service key\n");
        cfg_free(cfg);
        return -3;
      }
    }
    if (service_key_version > 255) {
      errorf("ERROR: Key version %ld too large, must fit into 8-bit int\n",
             service_key_version);
      cfg_free(cfg);
      return -4;
    }
    if (service_key_version > 0 && config->service_key_id == 0) {
      config->service_key_id = service_key_version;
    }
    if (url_prefix != NULL && config->url_prefix == NULL) {
      config->url_prefix = strdup(url_prefix);
    }
  }

  cfg_free(cfg);
  return 0;
}
