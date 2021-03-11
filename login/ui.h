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

#ifndef UI_H_
#define UI_H_

#include <inttypes.h>
#include <stdio.h>

#include "crypto.h"

#define errorf(...) fprintf(stderr, __VA_ARGS__)

#define USERNAME_MAX 32

#if !defined(SYSCONFDIR)
#define SYSCONFDIR "/etc"
#endif

#define DEFAULT_CONFIG_FILE SYSCONFDIR "/glome/config"

#define DEFAULT_LOGIN_PATH "/bin/login"

#define DEFAULT_AUTH_DELAY 1
#define DEFAULT_INPUT_TIMEOUT 180
#define DEFAULT_USERNAME "root"

// Options
// obsolete: SKIP_LOCKDOWN (1 << 1)
#define REBOOT (1 << 2)
#define VERBOSE (1 << 3)
#define INSECURE (1 << 4)
#define SYSLOG (1 << 5)

typedef struct login_config {
  // Bitfield of options as described above.
  uint8_t options;

  // Username to log in as.
  const char* username;

  // Configuration file to parse.
  const char* config_path;

  // Login binary for fallback authentication.
  const char* login_path;

  // Username triggering a reboot.
  const char* reboot_user;

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
} login_config_t;

// decode_hex converts a hex-encoded string into the equivalent bytes.
int decode_hex(uint8_t* dst, size_t dst_len, const char* in);

// parse_args parses command-line arguments into a config struct. It will
// forcefully initialize the whole content of the struct to zero.
int parse_args(login_config_t* config, int argc, char* argv[]);

// postprocess_config updates the configuration based on implied configuration
// in the input.
int postprocess_config(login_config_t* config);

// read_stdin reads printable characters from stdin into buf. It returns:
// -1, if it encounters an error while reading
// -2, if it encounters EOF
// (buflen-1) if it read buflen-1 characters
// <(buflen-1), if a newline was read before the buffer was full
// If the return value is >=0, the buf is NULL-terminated.
int read_stdin(char* buf, size_t buflen);

void print_hex(const uint8_t* buf, size_t len);

#endif  // UI_H_
