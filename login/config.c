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
#include <glib.h>
#include <string.h>

#include "ui.h"

int parse_config_file(login_config_t* config) {
  g_autofree gchar* service_key = NULL;
  guint64 service_key_version = 0;
  g_autofree gchar* url_prefix = NULL;
  g_autoptr(GKeyFile) cfg = g_key_file_new();
  g_autoptr(GError) error = NULL;

  bool required = config->config_path != NULL;
  if (!required) {
    config->config_path = DEFAULT_CONFIG_FILE;
  }

  gboolean loaded = g_key_file_load_from_file(cfg, config->config_path,
                                              G_KEY_FILE_NONE, &error);
  if (required && !loaded) {
    errorf("ERROR: config file could not be read: %s\n", error->message);
    return -1;
  }

  service_key = g_key_file_get_value(cfg, "service", "key", NULL);
  if (service_key != NULL &&
      is_zeroed(config->service_key, sizeof config->service_key)) {
    if (decode_hex(config->service_key, sizeof config->service_key,
                   service_key)) {
      errorf("ERROR: Failed to hex decode service key\n");
      return -2;
    }
  }

  service_key_version =
      g_key_file_get_uint64(cfg, "service", "key-version", NULL);
  if (service_key_version > 255) {
    errorf("ERROR: Key version %" G_GUINT64_FORMAT " too large, must fit into ",
           "8-bit int\n",
           service_key_version);
    return -3;
  }
  if (service_key_version > 0 && config->service_key_id == 0) {
    config->service_key_id = service_key_version;
  }

  url_prefix = g_key_file_get_value(cfg, "service", "url-prefix", NULL);
  if (url_prefix != NULL && config->url_prefix == NULL) {
    config->url_prefix = strdup(url_prefix);
  }

  return 0;
}
