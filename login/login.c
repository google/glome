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

#include "login.h"

#include <assert.h>
#include <bits/local_lim.h>
#include <glib.h>
#include <glome.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "base64.h"
#include "crypto.h"
#include "lockdown.h"
#include "ui.h"

#define PROMPT "> "

// How many bytes of authorization code do we require.
// Each byte has 6-bits of entropy due to Base64 encoding.
//
// For an auth code consisting of 48 bits of entropy with one second delays
// between attempts, the probability of sustaining a brute-force attack lasting
// a year is ~99.9999888%.
//
// This can be calculated using: (1-2**(-N))**(365*24*60*60/delay)
// where N is the number of bits of token’s entropy and delay is in seconds.
//
// We increase this a bit more and choose 60-bits of entropy.
#define MIN_ENCODED_AUTHCODE_LEN 10

#define DMI_UUID_PATH "/sys/class/dmi/id/product_uuid"
#define DMI_UUID_SIZE 36

static int get_hostname(char* buf, size_t buflen) {
  if (gethostname(buf, buflen - 1) != 0) {
    return -1;
  }
  buf[buflen] = '\0';

  // Regular hostname is likely fully qualified, so stop here and return it.
  if (strchr(buf, '.') != NULL) {
    return 0;
  }

  // Retry using getaddrinfo to get an FQDN.
  struct addrinfo* res;
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_CANONNAME;
  int ret;
  if ((ret = getaddrinfo(buf, NULL, &hints, &res)) != 0) {
    return -1;
  }
  strncpy(buf, res->ai_canonname, buflen - 1);
  buf[buflen] = '\0';
  return 0;
}

static int failure(int code, const char** error_tag, const char* message) {
  if (error_tag != NULL && *error_tag == NULL) {
    *error_tag = message;
  }
  return code;
}

static int get_machine_id(char* buf, size_t buflen, const char** error_tag) {
  if (get_hostname(buf, buflen) == 0) {
    return 0;
  }
  if (DMI_UUID_SIZE + 1 > buflen) {
    return failure(EXITCODE_PANIC, error_tag, "dmi-uuid-size");
  }
  FILE* fd;
  fd = fopen(DMI_UUID_PATH, "r");
  if (fd != NULL) {
    errorf("Unable to obtain hostname. Using DMI UUID instead.\n");
    if (fread(buf, DMI_UUID_SIZE, 1, fd) == 1) {
      buf[DMI_UUID_SIZE] = '\0';
      fclose(fd);
      return 0;
    }
    errorf("ERROR reading DMI product UUID (eof=%d, err=%d)\n", feof(fd),
           ferror(fd));
    fclose(fd);
  } else {
    perror("ERROR opening DMI product UUID file");
  }
  return -1;
}

void timeout_handler(int unused_signal) {
  errorf("Timed out while waiting for user input.\n");
  exit(EXITCODE_TIMEOUT);
}

int shell_action(const char* user, char** action, size_t* action_len,
                 const char** error_tag) {
  size_t buf_len = strlen("shell/") + strlen(user) + 1;
  char* buf = calloc(buf_len, 1);
  if (buf == NULL) {
    return failure(EXITCODE_PANIC, error_tag, "message-calloc-error");
  }
  int ret = snprintf(buf, buf_len, "shell/%s", user);
  if (ret < 0) {
    free(buf);
    return failure(EXITCODE_PANIC, error_tag, "message-sprintf-error");
  }
  if (ret >= buf_len) {
    free(buf);
    return failure(EXITCODE_PANIC, error_tag, "message-sprintf-trunc");
  }

  *action = buf;
  *action_len = buf_len;
  return 0;
}

int request_url(const uint8_t service_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                int service_key_id, const uint8_t public_key[PUBLIC_KEY_LENGTH],
                const char* host_id, const char* action,
                const uint8_t prefix_tag[GLOME_MAX_TAG_LENGTH],
                size_t prefix_tag_len, char** url, int* url_len,
                const char** error_tag) {
  if (prefix_tag_len >= GLOME_MAX_TAG_LENGTH) {
    return failure(EXITCODE_PANIC, error_tag, "prefix-tag-too-large");
  }
  // glome-handshake := base64url(
  //  <prefix-type>
  //  <prefix7>
  //  <eph-key>
  //  [<prefixN>]
  //)
  uint8_t handshake[PUBLIC_KEY_LENGTH + 1 + GLOME_MAX_TAG_LENGTH] = {0};
  size_t handshake_len = PUBLIC_KEY_LENGTH + 1 + prefix_tag_len;

  // From the reserved characters (! * ' ( ) ; : @ & = + $ , / ? # [ ])
  // it is only /, ?, and # that would be problematic at this particular place
  // in the URL.
  char* host_id_escaped = g_uri_escape_string(host_id, "!*'();:@&=+$,[]",
                                              /*allow_utf8=*/true);

  if (service_key_id == 0) {
    // If no key ID was specified, send the first key byte as the ID.
    handshake[0] = service_key[0] & 0x7f;
  } else {
    handshake[0] = service_key_id & 0x7f;
  }

  memcpy(handshake + 1, public_key, PUBLIC_KEY_LENGTH);
  if (prefix_tag_len > 0) {
    memcpy(handshake + PUBLIC_KEY_LENGTH + 1, prefix_tag, prefix_tag_len);
  }

  char handshake_encoded[ENCODED_BUFSIZE(sizeof handshake)] = {0};
  if (!base64url_encode(handshake, handshake_len, (uint8_t*)handshake_encoded,
                        sizeof handshake_encoded)) {
    return failure(EXITCODE_PANIC, error_tag, "handshake-encode");
  }

  int len = strlen("/v1/") + strlen(handshake_encoded) + 1 +
            strlen(host_id_escaped) + 1 + strlen(action) + 2;
  char* buf = malloc(len);
  if (buf == NULL) {
    free(host_id_escaped);
    return failure(EXITCODE_PANIC, error_tag, "url-malloc-error");
  }
  int ret = snprintf(buf, len, "/v1/%s/%s/%s/", handshake_encoded,
                     host_id_escaped, action);
  free(host_id_escaped);
  host_id_escaped = NULL;
  if (ret < 0) {
    free(buf);
    return failure(EXITCODE_PANIC, error_tag, "url-sprintf-error");
  }
  if (ret >= len) {
    free(buf);
    return failure(EXITCODE_PANIC, error_tag, "url-sprintf-trunc");
  }

  *url = buf;
  *url_len = len;
  return 0;
}

int login_run(login_config_t* config, const char** error_tag) {
  assert(config != NULL);
  if (config->options & VERBOSE) {
    errorf(
        "debug: options: 0x%x\n"
        "debug: username: %s\n"
        "debug: login: %s\n"
        "debug: auth delay: %d seconds\n",
        config->options, config->username, config->login_path,
        config->auth_delay_sec);
  }
  if (config->options & SYSLOG) {
    openlog("otac-login", LOG_PID | LOG_CONS, LOG_AUTH);
  }

  // Reboot the machine if requested before checking lockdown mode.
  if (config->options & REBOOT) {
    if (config->options & SYSLOG) {
      syslog(LOG_INFO, "requested reboot");
    }
    puts("rebooting machine...");
    fflush(NULL);
    // reboot the system by sending SIGINT to init (per init(8) manpage)
    if (kill(1, SIGINT) != 0) {
      perror("ERROR while sending SIGINT to init");
      return failure(EXITCODE_PANIC, error_tag, "sigint-to-init");
    }
    // Anyone with serial console access is likely authorized to powercycle the
    // machine, so we don't have to handle the case when init is uncooperative.
    return EXITCODE_REBOOT;
  }

  if ((config->options & SKIP_LOCKDOWN) == 0) {
    int lockdown = check_lockdown(config->lockdown_path);
    switch (lockdown) {
      case LOCKDOWN_DISABLED:
        break;
      case LOCKDOWN_ENABLED:
        return failure(EXITCODE_LOCKDOWN, error_tag, "lockdown-enabled");
      default:
        return failure(EXITCODE_LOCKDOWN_ERROR, error_tag,
                       "unknown-lockdown-state");
    }
  }

  if (is_zeroed(config->service_key, sizeof config->service_key)) {
    return failure(EXITCODE_PANIC, error_tag, "no-service-key");
  }

  uint8_t public_key[PUBLIC_KEY_LENGTH] = {0};
  if (derive_or_generate_key(config->secret_key, public_key)) {
    return failure(EXITCODE_PANIC, error_tag, "derive-or-generate-key");
  }

  char* host_id = NULL;
  if (config->host_id != NULL) {
    size_t s = strlen(config->host_id) + 1;
    host_id = calloc(s, 1);
    strncpy(host_id, config->host_id, s);
  } else {
    host_id = calloc(HOST_NAME_MAX + 1, 1);
    if (get_machine_id(host_id, HOST_NAME_MAX + 1, error_tag) < 0) {
      return failure(EXITCODE_PANIC, error_tag, "get-machine-id");
    }
  }

  char* action = NULL;
  size_t action_len = 0;

  if (shell_action(config->username, &action, &action_len, error_tag)) {
    free(host_id);
    return EXITCODE_PANIC;
  }

  uint8_t authcode[GLOME_MAX_TAG_LENGTH];
  if (get_authcode(host_id, action, config->service_key, config->secret_key,
                   authcode)) {
    free(host_id);
    free(action);
    return failure(EXITCODE_PANIC, error_tag, "get-authcode");
  }

  char* url = NULL;
  int url_len = 0;
  if (request_url(config->service_key, config->service_key_id, public_key,
                  host_id, action, /*prefix_tag=*/NULL,
                  /*prefix_tag_len=*/0, &url, &url_len, error_tag)) {
    free(host_id);
    free(action);
    return EXITCODE_PANIC;
  }

  free(host_id);
  host_id = NULL;
  free(action);
  action = NULL;

  printf("Obtain the one-time authorization code from:\n%s%s\n",
         config->url_prefix, url);

  free(url);
  url = NULL;

  // Display prompt.
  fputs(PROMPT, stdout);
  fflush(NULL);

  if (config->input_timeout_sec) {
    struct sigaction action;
    action.sa_handler = &timeout_handler;
    if (sigaction(SIGALRM, &action, NULL) < 0) {
      perror("error while setting up the handler");
      // Continue nonetheless as the handler is not critical.
    }
    // Set an alarm to prevent waiting for the code indefinitely.
    alarm(config->input_timeout_sec);
  }

  // Calculate the correct authcode.
  char authcode_encoded[ENCODED_BUFSIZE(sizeof authcode)] = {0};
  if (base64url_encode(authcode, sizeof authcode, (uint8_t*)authcode_encoded,
                       sizeof authcode_encoded) == 0) {
    return failure(EXITCODE_PANIC, error_tag, "authcode-encode");
  }

  char input[ENCODED_BUFSIZE(GLOME_MAX_TAG_LENGTH)];
  int bytes_read = read_stdin(input, sizeof input);

  // Cancel any pending alarms.
  alarm(0);

  if (bytes_read < 0) {
    return EXITCODE_IO_ERROR;
  }
  if (config->options & VERBOSE) {
    errorf("debug: stdin: ");
    print_hex((uint8_t*)input, bytes_read);
  }

  if (bytes_read < MIN_ENCODED_AUTHCODE_LEN) {
    if (config->options & SYSLOG) {
      syslog(LOG_INFO, "authcode too short: %d bytes (%s)", bytes_read,
             config->username);
    }
    printf("Input too short: expected at least %d characters, got %d.\n",
           MIN_ENCODED_AUTHCODE_LEN, bytes_read);
    return EXITCODE_INVALID_INPUT_SIZE;
  }
  if (bytes_read > strlen(authcode_encoded)) {
    if (config->options & SYSLOG) {
      syslog(LOG_INFO, "authcode too long: %d bytes (%s)", bytes_read,
             config->username);
    }
    printf("Input too long: expected at most %zu characters, got %d.\n",
           strlen(authcode_encoded), bytes_read);
    return EXITCODE_INVALID_INPUT_SIZE;
  }

  // Since we use (relatively) short auth codes, sleep before confirming the
  // result to prevent bruteforcing.
  struct timespec delay;
  delay.tv_sec = (time_t)config->auth_delay_sec;
  delay.tv_nsec = 0;
  if (nanosleep(&delay, NULL) != 0) {
    perror("interrupted sleep()");
    return EXITCODE_INTERRUPTED;
  }

  // We can use insecure strncmp() because it's a *one-time* code.
  if (strncmp(input, authcode_encoded, bytes_read) != 0) {
    if (config->options & SYSLOG) {
      syslog(LOG_WARNING, "authcode rejected (%s)", config->username);
    }
    puts("Invalid authorization code.");
    return EXITCODE_INVALID_AUTHCODE;
  }

  if (config->options & SYSLOG) {
    syslog(LOG_WARNING, "authcode accepted (%s)", config->username);
  }
  puts("Authorization code: OK");
  fflush(NULL);

  execl(config->login_path, config->login_path, "-f", config->username,
        (char*)NULL);
  perror("ERROR while executing login");
  return failure(EXITCODE_PANIC, error_tag, "login-exec");
}
