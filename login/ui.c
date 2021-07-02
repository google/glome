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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char* argv0) {
  const char* sep = strrchr(argv0, '/');
  const char* name = (sep == NULL) ? argv0 : sep + 1;
  errorf("Usage: %s [OPTIONS] [--] USERNAME\n", name);
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
    "\n -h        this help"

    "\n -c        configuration file to parse "
    "(default: " DEFAULT_CONFIG_FILE
    ")"

    "\n -d N      sleep N seconds before the auth code check (default: %d)"

    "\n -k KEY    use hex-encoded KEY as the service key (defaults to key "
    "from configuration file)"

    "\n -l PATH   use PATH instead of " DEFAULT_LOGIN_PATH

    "\n -u URL    use given URL prefix"

    "\n -s        suppress syslog logging (default: false)"

    "\n -t N      abort if the authcode has not been provided within N seconds"
    "             no timeout if the flag is 0 (default: %d)"

    "\n -v        print debug information"

    "\nUnsafe flags:"
    "\n -I        print all the secrets (INSECURE!)"
    "\n -K KEY    use KEY as the hex-encoded ephemeral secret key (INSECURE!)"
    "\n -M NAME   use NAME as the host-id"
    "\n";

int parse_args(glome_login_config_t* config, int argc, char* argv[]) {
  memset(config, 0, sizeof(glome_login_config_t));

  // Setting defaults.
  config->login_path = DEFAULT_LOGIN_PATH;
  config->url_prefix = NULL;
  config->auth_delay_sec = DEFAULT_AUTH_DELAY;
  config->input_timeout_sec = DEFAULT_INPUT_TIMEOUT;
  config->options = SYSLOG;

  int errors = 0;

  int c;
  while ((c = getopt(argc, argv, "hc:d:k:l:st:u:vIK:M:")) != -1) {
    char* endptr;
    long l;
    switch (c) {
      case 'c':
        config->config_path = optarg;
        break;
      case 'd':
        errno = 0;
        l = strtol(optarg, &endptr, 0);
        if (errno) {
          perror("ERROR: invalid value for -d");
          errors++;
          continue;
        }
        if (*endptr != '\0' || l < 0 || l > UINT_MAX) {
          errorf("ERROR: invalid value for -d: '%s'\n", optarg);
        }
        config->auth_delay_sec = (unsigned int)l;
        break;
      case 'k':
        if (decode_hex(config->service_key, sizeof config->service_key,
                       optarg) != 0) {
          errors++;
        }
        break;
      case 'l':
        config->login_path = optarg;
        break;
      case 's':
        config->options &= ~SYSLOG;
        break;
      case 't':
        errno = 0;
        l = strtol(optarg, &endptr, 0);
        if (errno) {
          perror("ERROR: invalid value for -t");
          errors++;
          continue;
        }
        if (*endptr != '\0' || l < 0 || l > UINT_MAX) {
          errorf("ERROR: invalid value for -t: '%s'\n", optarg);
        }
        config->input_timeout_sec = (unsigned int)l;
        break;
      case 'u':
        config->url_prefix = optarg;
        break;
      case 'v':
        config->options |= VERBOSE;
        break;
      case 'I':
        config->options |= INSECURE;
        break;
      case 'K':
        if (decode_hex(config->secret_key, sizeof config->secret_key, optarg) !=
            0) {
          errors++;
        }
        break;
      case 'M':
        config->host_id = optarg;
        break;
      case '?':
      case 'h':
        usage(argv[0]);
        errorf(flags_help, DEFAULT_AUTH_DELAY, DEFAULT_INPUT_TIMEOUT);
        return 2;
      default:
        return -1;  // PANIC
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

int postprocess_config(glome_login_config_t* config) {
  if (strlen(config->username) > USERNAME_MAX) {
    return -1;
  }
  return 0;
}

