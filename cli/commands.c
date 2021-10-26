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

#include "commands.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "glome.h"
#include "login/base64.h"
#include "login/crypto.h"

#define GLOME_CLI_MAX_MESSAGE_LENGTH 4095

#define UNUSED(var) (void)(var)

// Arguments
static const char *key_file = NULL;
static const char *peer_file = NULL;
static const char *tag_hex = NULL;
static unsigned long counter = 0;

static bool parse_args(int argc, char **argv) {
  struct option long_options[] = {{"key", required_argument, 0, 'k'},
                                  {"peer", required_argument, 0, 'p'},
                                  {"counter", required_argument, 0, 'c'},
                                  {"tag", required_argument, 0, 't'},
                                  {0, 0, 0, 0}};

  int c;
  while ((c = getopt_long(argc, argv, "c:k:p:t:", long_options, NULL)) != -1) {
    switch (c) {
      case 'c': {
        char *endptr;
        counter = strtoul(optarg, &endptr, 0);
        if (counter > UCHAR_MAX || optarg[0] == '\0' || *endptr != '\0') {
          fprintf(stderr, "'%s' is not a valid counter (0..255)\n", optarg);
          return false;
        }
        break;
      }
      case 'k':
        key_file = optarg;
        break;
      case 'p':
        peer_file = optarg;
        break;
      case 't':
        tag_hex = optarg;
        break;
      case '?':
        return false;
      default:
        // option not implemented
        abort();
    }
  }
  return true;
}

static int decode_hex(uint8_t *dst, size_t dst_len, const char *in) {
  size_t len = strlen(in);
  if (len > 2 && in[0] == '0' && in[1] == 'x') {
    len -= 2;
    in += 2;
  }
  if (len > dst_len * 2 || len % 2 != 0) {
    return -1;
  }
  size_t i;
  for (i = 0; i < len / 2; i++) {
    if (sscanf(in + (i * 2), "%02hhX", dst + i) != 1) {
      fprintf(stderr, "ERROR while parsing byte %zu ('%c%c') as hex\n", i,
              in[2 * i], in[2 * i + 1]);
      return -3;
    }
  }
  return i;
}

static bool read_file(const char *fname, uint8_t *buf, const size_t num_bytes) {
  FILE *f = fopen(fname, "r");
  if (!f) {
    fprintf(stderr, "could not open file %s: %s\n", fname, strerror(errno));
    return false;
  }
  if (fread(buf, 1, num_bytes, f) != num_bytes) {
    fprintf(stderr, "could not read %zu bytes from file %s", num_bytes, fname);
    if (ferror(f)) {
      fprintf(stderr, ": %s\n", strerror(errno));
    } else {
      fputs("\n", stderr);
    }
    fclose(f);
    return false;
  }
  fclose(f);
  return true;
}

static void print_hex(FILE *stream, const char *prefix, uint8_t *buf,
                      size_t len) {
  if (prefix != NULL) {
    fputs(prefix, stream);
  }
  for (size_t i = 0; i < len; i++) {
    fprintf(stream, "%02x", buf[i]);
  }
  fputs("\n", stream);
}

int genkey(int argc, char **argv) {
  UNUSED(argc);
  UNUSED(argv);

  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};

  if (glome_generate_key(private_key, NULL)) {
    fprintf(stderr, "unable to generate a new key\n");
    return EXIT_FAILURE;
  }
  if (fwrite(private_key, 1, sizeof private_key, stdout) !=
      sizeof private_key) {
    perror("unable to write the private key to stdout");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

int pubkey(int argc, char **argv) {
  UNUSED(argc);
  UNUSED(argv);

  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};

  if (fread(private_key, 1, sizeof private_key, stdin) != sizeof private_key) {
    perror("unable to read the private key from stdin");
    return EXIT_FAILURE;
  }
  if (glome_derive_key(private_key, public_key)) {
    fprintf(stderr, "unable to generate a new key\n");
    return EXIT_FAILURE;
  }
  if (fwrite(public_key, 1, sizeof public_key, stdout) != sizeof public_key) {
    perror("unable to write the public key to stdout");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// tag_impl reads a private key and a peer key from the given files and computes
// a tag corresponding to a message read from stdin for the communication
// direction determined by verify.
int tag_impl(uint8_t tag[GLOME_MAX_TAG_LENGTH], bool verify,
             const char *key_file, const char *peer_file) {
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  char message[GLOME_CLI_MAX_MESSAGE_LENGTH] = {0};

  if (!read_file(key_file, private_key, sizeof private_key) ||
      !read_file(peer_file, peer_key, sizeof peer_key)) {
    return EXIT_FAILURE;
  };
  size_t msg_len = fread(message, 1, GLOME_CLI_MAX_MESSAGE_LENGTH, stdin);
  if (!feof(stdin)) {
    fprintf(stderr, "message exceeds maximum supported size of %u",
            GLOME_CLI_MAX_MESSAGE_LENGTH);
    return EXIT_FAILURE;
  }
  if (glome_tag(verify, counter, private_key, peer_key, (uint8_t *)message,
                msg_len, tag)) {
    fputs("MAC tag generation failed", stderr);
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

int tag(int argc, char **argv) {
  uint8_t tag[GLOME_MAX_TAG_LENGTH] = {0};
  if (!parse_args(argc, argv)) {
    return EXIT_FAILURE;
  }
  if (!key_file || !peer_file) {
    fprintf(stderr, "not enough arguments for subcommand %s\n", argv[1]);
    return EXIT_FAILURE;
  }
  int res = tag_impl(tag, /*verify=*/false, key_file, peer_file);
  if (res) {
    return res;
  }
  print_hex(stdout, "", tag, sizeof tag);
  return EXIT_SUCCESS;
}

int verify(int argc, char **argv) {
  uint8_t tag[GLOME_MAX_TAG_LENGTH] = {0};
  uint8_t expected_tag[GLOME_MAX_TAG_LENGTH] = {0};
  size_t expected_tag_len = 0;
  if (!parse_args(argc, argv)) {
    return EXIT_FAILURE;
  }
  if (!key_file || !peer_file || !tag_hex) {
    fprintf(stderr, "not enough arguments for subcommand %s\n", argv[1]);
    return EXIT_FAILURE;
  }
  int res = tag_impl(tag, /*verify=*/true, key_file, peer_file);
  if (res) {
    return res;
  }

  // compare the tag
  expected_tag_len = decode_hex(expected_tag, sizeof expected_tag, tag_hex);
  if (CRYPTO_memcmp(expected_tag, tag, expected_tag_len) != 0) {
    fputs("MAC tag verification failed", stderr);
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

static bool parse_login_path(char *path, char **handshake, char **host,
                             char **action) {
  size_t path_len = strlen(path);
  if (path_len < 4 || path[0] != '/' || path[1] != 'v' || path[2] != '1' ||
      path[3] != '/') {
    fprintf(stderr, "unexpected url path prefix: %s\n", path);
    return false;
  }
  if (path[path_len - 1] != '/') {
    fprintf(stderr, "unexpected url path suffix: %s\n", path);
    return false;
  }

  char *start = path + 4;
  char *slash = strchr(start, '/');
  if (slash == NULL || slash - start == 0) {
    fprintf(stderr, "could not parse handshake from %s\n", start);
    return false;
  }
  *handshake = strndup(start, slash - start);
  if (*handshake == NULL) {
    fprintf(stderr, "failed to duplicate handshake\n");
    return false;
  }

  start = slash + 1;
  slash = strchr(start, '/');
  if (slash == NULL || slash - start == 0) {
    free(*handshake);
    *handshake = NULL;
    fprintf(stderr, "could not parse host from %s\n", start);
    return false;
  }
  *host = strndup(start, slash - start);
  if (*host == NULL) {
    free(*handshake);
    *handshake = NULL;
    fprintf(stderr, "failed to duplicate host\n");
    return false;
  }

  // Everything left (not including the trailing slash) is an action. It may
  // include slashes and it can also be empty.
  start = slash + 1;
  *action = strndup(start, path + path_len - 1 - start);
  if (*action == NULL) {
    free(*host);
    *host = NULL;
    free(*handshake);
    *handshake = NULL;
    fprintf(stderr, "failed to duplicate action\n");
    return false;
  }

  return true;
}

static int unhex(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  } else if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  } else {
    return -1;
  }
}

static char *uri_unescape(char *e) {
  size_t len = strlen(e);
  char *u = malloc(len + 1);
  if (u == NULL) {
    return NULL;
  }

  size_t i, j;
  for (i = 0, j = 0; i < len; j++) {
    if (e[i] != '%') {
      u[j] = e[i];
      i += 1;
      continue;
    }
    if (i + 2 >= len) {
      goto fail;
    }
    int n = unhex(e[i + 1]);
    if (n < 0) {
      goto fail;
    }
    u[j] = (char)(n << 4);
    n = unhex(e[i + 2]);
    if (n < 0) {
      goto fail;
    }
    u[j] |= (char)n;
    i += 3;
  }
  u[j] = '\0';
  return u;

fail:
  free(u);
  return NULL;
}

int login(int argc, char **argv) {
  char *handshake = NULL;
  char *handshake_b64 = NULL;
  char *host = NULL;
  char *host_esc = NULL;
  char *action = NULL;
  int ret = EXIT_FAILURE;

  if (!parse_args(argc, argv)) {
    return EXIT_FAILURE;
  }
  char *cmd = argv[optind++];
  if (optind >= argc) {
    fprintf(stderr, "missing url path argument for subcommand %s\n", cmd);
    return EXIT_FAILURE;
  }

  if (!key_file) {
    fprintf(stderr, "not enough arguments for subcommand %s\n", cmd);
    return EXIT_FAILURE;
  }
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  if (!read_file(key_file, private_key, sizeof private_key)) {
    return EXIT_FAILURE;
  }

  char *path = argv[optind];
  if (!parse_login_path(path, &handshake_b64, &host_esc, &action)) {
    return EXIT_FAILURE;
  }

  host = uri_unescape(host_esc);
  if (host == NULL) {
    fprintf(stderr, "failed to parse hostname in path %s\n", path);
    goto out;
  }

  size_t handshake_b64_len = strlen(handshake_b64);
  handshake = malloc(DECODED_BUFSIZE(handshake_b64_len));
  int handshake_len = base64url_decode((uint8_t *)handshake_b64,
                                       handshake_b64_len, (uint8_t *)handshake,
                                       DECODED_BUFSIZE(handshake_b64_len));
  if (handshake_len == 0) {
    fprintf(stderr, "failed to decode handshake in path %s\n", path);
    goto out;
  }
  if (handshake_len < 1 + GLOME_MAX_PUBLIC_KEY_LENGTH ||
      handshake_len > 1 + GLOME_MAX_PUBLIC_KEY_LENGTH + GLOME_MAX_TAG_LENGTH) {
    fprintf(stderr, "handshake size is invalid in path %s\n", path);
    goto out;
  }
  if ((handshake[0] & 0x80) != 0) {
    fprintf(stderr,
            "only \"service-key-indicator\" prefix type is supported\n");
    goto out;
  }
  uint8_t peer_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  memcpy(peer_key, handshake + 1, GLOME_MAX_PUBLIC_KEY_LENGTH);

  uint8_t tag[GLOME_MAX_TAG_LENGTH] = {0};
  if (get_authcode(host, action, peer_key, private_key, tag)) {
    fprintf(stderr, "MAC authcode generation failed\n");
    goto out;
  }
  if (CRYPTO_memcmp(handshake + 1 + GLOME_MAX_PUBLIC_KEY_LENGTH, tag,
                    handshake_len - 1 - GLOME_MAX_PUBLIC_KEY_LENGTH) != 0) {
    fprintf(stderr,
            "The URL includes a message tag prefix which does not match the "
            "message\n");
    goto out;
  }

  if (get_msg_tag(host, action, peer_key, private_key, tag)) {
    fprintf(stderr, "GLOME tag generation failed\n");
    goto out;
  }
  char tag_encoded[ENCODED_BUFSIZE(sizeof tag)] = {0};
  if (base64url_encode(tag, sizeof tag, (uint8_t *)tag_encoded,
                       sizeof tag_encoded) == 0) {
    fprintf(stderr, "GLOME tag encode failed\n");
    goto out;
  }
  puts(tag_encoded);
  ret = EXIT_SUCCESS;

out:
  free(handshake);
  free(host);
  free(handshake_b64);
  free(host_esc);
  free(action);
  return ret;
}
