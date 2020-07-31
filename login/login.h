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

#ifndef LOGIN_H_
#define LOGIN_H_

#include <glome.h>

#include "ui.h"

// All exit codes from login_run/main
#define EXITCODE_USAGE 1
#define EXITCODE_REBOOT 2
#define EXITCODE_LOCKDOWN 3
#define EXITCODE_IO_ERROR 4
#define EXITCODE_INVALID_AUTHCODE 5
#define EXITCODE_INVALID_INPUT_SIZE 6
#define EXITCODE_INTERRUPTED 7
#define EXITCODE_LOCKDOWN_ERROR 8
#define EXITCODE_TIMEOUT 9
#define EXITCODE_PANIC 42

// login_run executes the main login logic challenging the user for an
// authenticate code unless fallback authentication has been requested.
//
// On error, the error_tag is set to an error token which should NOT be freed.
int login_run(login_config_t* config, const char** error_tag);

// Constructs the action requesting shell access as a given user.
//
// Caller is expected to free returned message.
// On error, the error_tag is set to an error token which should NOT be freed.
int shell_action(const char* user, char** action, size_t* action_len,
                 const char** error_tag);

// Construct a request URL given the key parameters, host ID, an action, and
// optionally a message prefix tag.
//
// The length of the message prefix tag is in bytes. Only tag sizes of multiples
// by 8 is supported.
//
// Caller is expected to free returned URL.
// On error, the error_tag is set to an error token which should NOT be freed.
int request_url(const uint8_t service_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                int service_key_id, const uint8_t public_key[PUBLIC_KEY_LENGTH],
                const char* host_id, const char* action,
                const uint8_t prefix_tag[GLOME_MAX_TAG_LENGTH],
                size_t prefix_tag_len, char** url, int* url_len,
                const char** error_tag);

#endif  // LOGIN_H_
