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

// For vsyslog
#define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include "login.h"

#include <assert.h>
#include <errno.h>
#include <glome.h>
#include <limits.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdarg.h>
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
#include "ui.h"

#define PROMPT "> "

#define DMI_UUID_PATH "/sys/class/dmi/id/product_uuid"
#define DMI_UUID_SIZE 36

#define UNUSED(var) (void)(var)

static int get_hostname(char* buf, size_t buflen) {
  if (gethostname(buf, buflen) != 0) {
    return -1;
  }
  buf[buflen - 1] = '\0';

  // Regular hostname is likely fully qualified, so stop here and return it.
  if (strchr(buf, '.') != NULL) {
    return 0;
  }

  // Retry using getaddrinfo to get an FQDN.
  struct addrinfo* res = NULL;
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_CANONNAME;
  int ret;
  if ((ret = getaddrinfo(buf, NULL, &hints, &res)) != 0) {
    return -1;
  }
  strncpy(buf, res->ai_canonname, buflen - 1);
  buf[buflen - 1] = '\0';
  freeaddrinfo(res);
  return 0;
}

int failure(int code, const char** error_tag, const char* message) {
  if (error_tag != NULL && *error_tag == NULL) {
    *error_tag = message;
  }
  return code;
}

int get_machine_id(char* buf, size_t buflen, const char** error_tag) {
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

void timeout_handler(int sig) {
  UNUSED(sig);
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
  if ((size_t)ret >= buf_len) {
    free(buf);
    return failure(EXITCODE_PANIC, error_tag, "message-sprintf-trunc");
  }

  *action = buf;
  *action_len = buf_len;
  return 0;
}

char* escape_host(const char* host) {
  size_t host_len = strlen(host);
  char *ret = malloc(host_len * 3 + 1), *ret_end = ret;
  if (ret == NULL) {
    return NULL;
  }
  // Only /, ?, and # would be problematic given our URL encoding
  for (size_t i = 0; i < host_len; ++i) {
    if (host[i] == '/' || host[i] == '?' || host[i] == '#') {
      sprintf(ret_end, "%%%02X", host[i]);
      ret_end += 3;
    } else {
      ret_end[0] = host[i];
      ret_end += 1;
    }
  }
  ret_end[0] = '\0';
  return ret;
}

int request_url(const uint8_t service_key[GLOME_MAX_PUBLIC_KEY_LENGTH],
                int service_key_id, const uint8_t public_key[PUBLIC_KEY_LENGTH],
                const char* host_id, const char* action,
                const uint8_t prefix_tag[GLOME_MAX_TAG_LENGTH],
                size_t prefix_tag_len, char** url, int* url_len,
                const char** error_tag) {
  if (prefix_tag_len > GLOME_MAX_TAG_LENGTH) {
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

  char* host_id_escaped = escape_host(host_id);
  if (host_id_escaped == NULL) {
    return failure(EXITCODE_PANIC, error_tag, "host-id-malloc-error");
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

#ifndef PAM_GLOME
void login_error(glome_login_config_t* config, pam_handle_t* pamh,
                 const char* format, ...) {
  UNUSED(config);
  UNUSED(pamh);
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fflush(NULL);
}

void login_syslog(glome_login_config_t* config, pam_handle_t* pamh,
                  int priority, const char* format, ...) {
  UNUSED(pamh);
  if (config->options & SYSLOG) {
    va_list args;
    va_start(args, format);
    vsyslog(priority, format, args);
    va_end(args);
  }
}

// read_stdin reads characters from stdin into buf. It returns:
// -1, if it encounters an error while reading
// -2, if it encounters invalid characters in the input
// (buflen-1) if it read buflen-1 characters
// <(buflen-1), if a newline was read before the buffer was full
// If the return value is >=0, the buf is NULL-terminated.
// Additionally, stdin is always advanced up to a newline (or EOF)
// to prevent excess input from being read by a future shell process.
static int read_stdin(char* buf, int buflen) {
  // Return error if we got no characters.
  if (fgets(buf, buflen, stdin) == NULL) {
    perror("ERROR when reading from stdin");
    return -1;
  }

  bool newline = false;
  int len = strlen(buf);
  if (buf[len - 1] == '\n') {
    newline = true;
    buf[len - 1] = '\0';
    len--;
  }

  // Return error if we got a non-printable character.
  for (int i = 0; i < len; i++) {
    if (buf[i] < 0x20 || buf[i] > 0x7e) {
      errorf("ERROR invalid characters read from stdin\n");
      return -2;
    }
  }

  // Read stdin until a newline to avoid passing junk to shell.
  if (!newline) {
    for (int c = 0; c != EOF && c != '\n'; c = fgetc(stdin)) {
    }
  }

  return len;  // Number of characters in the buffer without the NULL byte.
}

static void print_hex(const uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    errorf("%02x", buf[i]);
  }
  errorf("\n");
}

int login_prompt(glome_login_config_t* config, pam_handle_t* pamh,
                 const char** error_tag, const char* message, char* input,
                 size_t input_size) {
  UNUSED(pamh);
  UNUSED(error_tag);

  puts(message);
  fputs(PROMPT, stdout);
  fflush(NULL);

  if (config->input_timeout_sec) {
    struct sigaction action = {.sa_handler = &timeout_handler};
    if (sigaction(SIGALRM, &action, NULL) < 0) {
      perror("error while setting up the handler");
      // Continue nonetheless as the handler is not critical.
    }
    // Set an alarm to prevent waiting for the code indefinitely.
    alarm(config->input_timeout_sec);
  }

  int bytes_read = read_stdin(input, input_size);

  // Cancel any pending alarms.
  alarm(0);

  if (bytes_read < 0) {
    return EXITCODE_IO_ERROR;
  }
  if (config->options & VERBOSE) {
    errorf("debug: stdin: ");
    print_hex((uint8_t*)input, bytes_read);
  }
  return 0;
}
#endif

int login_authenticate(glome_login_config_t* config, pam_handle_t* pamh,
                       const char* prompt_format, const char** error_tag) {
  if (is_zeroed(config->service_key, sizeof config->service_key)) {
    return failure(EXITCODE_PANIC, error_tag, "no-service-key");
  }

  uint8_t public_key[PUBLIC_KEY_LENGTH] = {0};
  if (derive_or_generate_key(config->secret_key, public_key)) {
    return failure(EXITCODE_PANIC, error_tag, "derive-or-generate-key");
  }

  char* host_id = NULL;
  if (config->host_id != NULL) {
    host_id = strdup(config->host_id);
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

  if (config->options & VERBOSE) {
    login_syslog(config, pamh, LOG_DEBUG, "host ID: %s, action: %s", host_id,
                 action);
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

  const char* prefix = "";
  if (config->url_prefix != NULL) {
    prefix = config->url_prefix;
  }
  size_t message_len =
      strlen(prompt_format) + strlen(prefix) - 2 + strlen(url) - 2 + 1;
  char* message = malloc(message_len);
  if (message == NULL) {
    return failure(EXITCODE_PANIC, error_tag, "malloc-message");
  }
  int written = snprintf(message, message_len, prompt_format, prefix, url);
  if (written < 0 || (size_t)written >= message_len) {
    free(message);
    return failure(EXITCODE_PANIC, error_tag, "broken-template");
  }
  free(url);
  url = NULL;

  char input[ENCODED_BUFSIZE(GLOME_MAX_TAG_LENGTH)];
  int rc = login_prompt(config, pamh, error_tag, message, input, sizeof(input));
  free(message);
  if (rc != 0) {
    return rc;
  }

  int bytes_read = strlen(input);
  if (config->options & INSECURE) {
    login_syslog(config, pamh, LOG_DEBUG, "user input: %s", input);
  }

  // Calculate the correct authcode.
  char authcode_encoded[ENCODED_BUFSIZE(sizeof authcode)] = {0};
  if (base64url_encode(authcode, sizeof authcode, (uint8_t*)authcode_encoded,
                       sizeof authcode_encoded) == 0) {
    return failure(EXITCODE_PANIC, error_tag, "authcode-encode");
  }
  if (config->options & INSECURE) {
    login_syslog(config, pamh, LOG_DEBUG, "expect input: %s", authcode_encoded);
  }

  if (bytes_read < MIN_ENCODED_AUTHCODE_LEN) {
    login_syslog(config, pamh, LOG_INFO, "authcode too short: %d bytes (%s)",
                 bytes_read, config->username);
    login_error(config, pamh,
                "Input too short: expected at least %d characters, got %d.\n",
                MIN_ENCODED_AUTHCODE_LEN, bytes_read);
    return failure(EXITCODE_INVALID_INPUT_SIZE, error_tag, "authcode-length");
  }
  if ((size_t)bytes_read > strlen(authcode_encoded)) {
    login_syslog(config, pamh, LOG_INFO, "authcode too long: %d bytes (%s)",
                 bytes_read, config->username);
    login_error(config, pamh,
                "Input too long: expected at most %zu characters, got %d.\n",
                strlen(authcode_encoded), bytes_read);
    return failure(EXITCODE_INVALID_INPUT_SIZE, error_tag, "authcode-length");
  }

  // Since we use (relatively) short auth codes, sleep before confirming the
  // result to prevent bruteforcing.
  if (config->auth_delay_sec) {
    struct timespec delay;
    delay.tv_sec = (time_t)config->auth_delay_sec;
    delay.tv_nsec = 0;
    if (nanosleep(&delay, NULL) != 0) {
      login_error(config, pamh, "interrupted sleep: %s", strerror(errno));
      return failure(EXITCODE_INTERRUPTED, error_tag, "sleep-interrupted");
    }
  }

  if (CRYPTO_memcmp(input, authcode_encoded, bytes_read) != 0) {
    login_syslog(config, pamh, LOG_WARNING, "authcode rejected (%s)",
                 config->username);
    login_error(config, pamh, "Invalid authorization code.\n");
    return failure(EXITCODE_INVALID_AUTHCODE, error_tag, "authcode-invalid");
  }

  return 0;
}

int login_run(glome_login_config_t* config, const char** error_tag) {
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
    openlog("glome-login", LOG_PID | LOG_CONS, LOG_AUTH);
  }

  int r = login_authenticate(
      config, NULL, "Obtain the one-time authorization code from:\n%s%s",
      error_tag);
  if (r != 0) {
    return r;
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
