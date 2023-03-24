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

#include "ui.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char* argv0) {
  const char* sep = strrchr(argv0, '/');
  const char* name = (sep == NULL) ? argv0 : sep + 1;
  errorf("Usage: %s [OPTIONS] [--] USERNAME\n", name);
}

#define STATUS_SIZE 256
static char* status_malloc_failed = "ERROR: failed to allocate status buffer";

status_t status_createf(const char* format, ...) {
  char* message = malloc(STATUS_SIZE);
  if (message == NULL) {
    return status_malloc_failed;
  }
  va_list argptr;
  va_start(argptr, format);
  int ret = vsnprintf(message, STATUS_SIZE, format, argptr);
  va_end(argptr);
  if (ret < 0 || ret >= STATUS_SIZE) {
    snprintf(message, STATUS_SIZE, "ERROR: status message too big: %d", ret);
  }
  return message;
}

void status_free(status_t status) {
  if (status == status_malloc_failed) {
    return;
  }
  free(status);
}

int decode_hex(uint8_t* dst, size_t dst_len, const char* in) {
  size_t len = strlen(in);
  if (len > 2 && in[0] == '0' && in[1] == 'x') {
    len -= 2;
    in += 2;
  }
  if (len != dst_len * 2) {
    errorf(
        "ERROR: hex-encoded key must have exactly %zu characters (got %zu)\n",
        dst_len * 2, len);
    return -1;
  }
  for (size_t i = 0; i < dst_len; i++) {
    if (sscanf(in + (i * 2), "%02hhX", dst + i) != 1) {
      errorf("ERROR while parsing byte %zu ('%c%c') as hex\n", i, in[2 * i],
             in[2 * i + 1]);
      return -2;
    }
  }
  return 0;
}

static const char flags_help[] =
    "Available flags:"
    "\n -h, --help                 this help"

    "\n -c, --config-path=PATH     configuration file to parse "
    "(default: " DEFAULT_CONFIG_FILE
    ")"

    "\n -a, --min-authcode-len=N   minimum length of the encoded authcode"

    "\n -d, --auth-delay=N         sleep N seconds before the authcode check "
    "(default: %d)"

    "\n -k, --key=KEY              use hex-encoded KEY as the service key "
    "(default: key from configuration file)"

    "\n -l, --login-path=PATH      use PATH instead of " DEFAULT_LOGIN_PATH

    "\n -p, --prompt=PROMPT        print PROMPT before the challenge is "
    "printed (default: '" DEFAULT_PROMPT
    "')"

    "\n -s, --disable-syslog       suppress syslog logging (default: false)"

    "\n -t, --timeout=N            abort if the authcode has not been provided "
    "within N seconds"
    "\n                            no timeout if the flag is 0 (default: %d)"

    "\n -v, --verbose              print debug information"

    "\nUnsafe flags:"
    "\n -I, --print-secrets        print all the secrets (INSECURE!)"
    "\n -K, --ephemeral-key=KEY    use KEY as the hex-encoded ephemeral secret "
    "key (INSECURE!)"
    "\n -M, --host-id=NAME         use NAME as the host-id"
    "\n";

static const char* short_options = "ha:c:d:k:l:p:st:u:vIK:M:";
static const struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"min-authcode-len", required_argument, 0, 'a'},
    {"config-path", required_argument, 0, 'c'},
    {"auth-delay", required_argument, 0, 'd'},
    {"key", required_argument, 0, 'k'},
    {"login-path", required_argument, 0, 'l'},
    {"disable-syslog", no_argument, 0, 's'},
    {"timeout", required_argument, 0, 't'},
    {"prompt", required_argument, 0, 'p'},
    {"verbose", no_argument, 0, 'v'},
    {"print-secrets", no_argument, 0, 'I'},
    {"ephemeral-key", required_argument, 0, 'K'},
    {"host-id", required_argument, 0, 'M'},
    {0, 0, 0, 0},
};

void default_config(glome_login_config_t* config) {
  memset(config, 0, sizeof(glome_login_config_t));

  // Setting defaults.
  config->login_path = DEFAULT_LOGIN_PATH;
  config->prompt = DEFAULT_PROMPT;
  config->auth_delay_sec = DEFAULT_AUTH_DELAY;
  config->input_timeout_sec = DEFAULT_INPUT_TIMEOUT;
  config->options = SYSLOG;
}

int parse_args(glome_login_config_t* config, int argc, char* argv[]) {
  int c;
  int errors = 0;
  status_t status;

  // Reset current position to allow parsing arguments multiple times.
  optind = 1;

  while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) !=
         -1) {
    switch (c) {
      case 'a':
        status = glome_login_assign_config_option(config, "default",
                                                  "min-authcode-len", optarg);
        break;
      case 'c':
        status = glome_login_assign_config_option(config, "default",
                                                  "config-path", optarg);
        break;
      case 'd':
        status = glome_login_assign_config_option(config, "default",
                                                  "auth-delay", optarg);
        break;
      case 'k':
        status =
            glome_login_assign_config_option(config, "service", "key", optarg);
        break;
      case 'l':
        status = glome_login_assign_config_option(config, "service",
                                                  "login-path", optarg);
        break;
      case 'p':
        status = glome_login_assign_config_option(config, "service", "prompt",
                                                  optarg);
        break;
      case 's':
        status = glome_login_assign_config_option(config, "default",
                                                  "disable-syslog", optarg);
        break;
      case 't':
        status = glome_login_assign_config_option(config, "default", "timeout",
                                                  optarg);
        break;
      case 'v':
        status = glome_login_assign_config_option(config, "default", "verbose",
                                                  optarg);
        break;
      case 'I':
        status = glome_login_assign_config_option(config, "default",
                                                  "print-secrets", optarg);
        break;
      case 'K':
        status = glome_login_assign_config_option(config, "default",
                                                  "ephemeral-key", optarg);
        break;
      case 'M':
        status = glome_login_assign_config_option(config, "default", "host-id",
                                                  optarg);
        break;
      case '?':
      case 'h':
        usage(argv[0]);
        errorf(flags_help, DEFAULT_AUTH_DELAY, DEFAULT_INPUT_TIMEOUT);
        return 2;
      default:
        return -1;  // PANIC
    }
    if (status != STATUS_OK) {
      errorf("%s\n", status);
      status_free(status);
      errors++;
    }
  }

  if (optind >= argc) {
    errorf("ERROR: no username specified\n");
    errors++;
  }

  if (optind < argc - 1) {
    errorf("ERROR: only one username is allowed (got %d)\n", argc - optind);
    errors++;
  }

  if (errors > 0) {
    usage(argv[0]);
    return 1;
  }

  config->username = argv[optind];
  return 0;
}
