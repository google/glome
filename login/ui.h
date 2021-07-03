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

#include "config.h"
#include "crypto.h"

#define errorf(...) fprintf(stderr, __VA_ARGS__)

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
// obsolete: REBOOT (1 << 2)
#define VERBOSE (1 << 3)
#define INSECURE (1 << 4)
#define SYSLOG (1 << 5)

// decode_hex converts a hex-encoded string into the equivalent bytes.
int decode_hex(uint8_t* dst, size_t dst_len, const char* in);

// parse_args parses command-line arguments into a config struct. It will
// forcefully initialize the whole content of the struct to zero.
int parse_args(glome_login_config_t* config, int argc, char* argv[]);

#endif  // UI_H_
