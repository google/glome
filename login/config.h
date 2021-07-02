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

#ifndef GLOME_LOGIN_CONFIG_H_
#define GLOME_LOGIN_CONFIG_H_

#include "crypto.h"

typedef struct glome_login_config {
  // Bitfield of options as described above.
  uint8_t options;

  // Username to log in as.
  const char* username;

  // Configuration file to parse.
  const char* config_path;

  // Login binary for fallback authentication.
  const char* login_path;

  // URL prefix to use for HTTP service.
  const char* url_prefix;

  // Delay to wait before confirming if the authentication code is valid
  // or not, to stop brute forcing; in seconds.
  unsigned int auth_delay_sec;

  // How long to wait for authentication code input in seconds.
  unsigned int input_timeout_sec;

  // Service key of the remote peer.
  uint8_t service_key[PUBLIC_KEY_LENGTH];

  // ID of the service key of the remote peer. (Optional)
  uint8_t service_key_id;

  // Local ephemeral secret key.
  uint8_t secret_key[PRIVATE_KEY_LENGTH];

  // Explicitly set host-id to use in the login request.
  const char* host_id;
} glome_login_config_t;

// glome_login_parse_config_file parses the configuration file and fills the
// given config struct with the data. The default config file is used in case
// no explicit config file has been provided, however in this case failed
// attempts to read the default config file will be ignored.
int glome_login_parse_config_file(glome_login_config_t* config);

#endif  // GLOME_LOGIN_CONFIG_H_
