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

#define GLOME_LOGIN_PUBLIC_KEY_ID "glome-v1"

// glome_login_parse_public_key extracts the public key bytes from an encoded
// public key.
// Returns true on success.
bool glome_login_parse_public_key(const char* encoded_key, uint8_t* public_key,
                                  size_t public_key_size);

// Error message returned by the config functions. If no error ocurred
// return value will be set to STATUS_OK.
typedef char* status_t;
// Allocate and format an error message.
status_t status_createf(const char* format, ...);
// Free an error message after it is not needed anymore.
void status_free(status_t status);
// If no error occurred the value of returned error message will be STATUS_OK.
#define STATUS_OK NULL

// glome_login_parse_config_file parses the configuration file and fills the
// given config struct with the data. The default config file is used in case
// no explicit config file has been provided, however in this case failed
// attempts to read the default config file will be ignored.
status_t glome_login_parse_config_file(glome_login_config_t* config);

status_t glome_login_assign_config_option(glome_login_config_t* config,
                                          const char* section, const char* key,
                                          const char* val);

#endif  // GLOME_LOGIN_CONFIG_H_
