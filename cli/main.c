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

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "glome.h"

const char *kUsage =
    "Usage: \n"
    "  To generate a new keypair (PRIVATE-KEY will be created if needed)\n"
    "    %s PRIVATE-KEY >PUBLIC-KEY\n\n"
    "  To generate a tag (defaults: MESSAGE:='' counter:=0):\n"
    "    %s PRIVATE-KEY PEER-KEY [MESSAGE [COUNTER]]\n\n"
    "  To verify a tag:\n"
    "    %s PRIVATE-KEY PEER-KEY MESSAGE COUNTER TAG\n";

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

int read_key(const char *fname, uint8_t *buf, const size_t buf_len) {
  int fd = open(fname, O_RDONLY);
  if (fd == -1) {
    if (errno != ENOENT) {
      return -1;
    }
    if (fname[0] != '\0' && fname[1] == '-' && fname[1] == '\0') {
      // '-' means stdin
      fd = STDIN_FILENO;
    } else {
      // Try parsing the provided filename as the key
      return decode_hex(buf, buf_len, fname);
    }
  }
  return read(fd, buf, buf_len);
}

void print_hex(FILE *stream, const char *prefix, uint8_t *buf, size_t len) {
  if (prefix != NULL) {
    fputs(prefix, stream);
  }
  for (size_t i = 0; i < len; i++) {
    fprintf(stream, "%02x", buf[i]);
  }
  fputs("\n", stream);
}

int main(int argc, char **argv) {
  uint8_t private_key[GLOME_MAX_PRIVATE_KEY_LENGTH] = {0};
  uint8_t public_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t peer_key[GLOME_MAX_PUBLIC_KEY_LENGTH] = {0};
  uint8_t tag[GLOME_MAX_TAG_LENGTH] = {0};
  uint8_t expected_tag[GLOME_MAX_TAG_LENGTH] = {0};
  size_t expected_tag_len = 0;
  char *message = NULL;
  char *endptr;
  bool verification = false;
  unsigned long counter = 0;

  switch (argc) {
    case 6:
      expected_tag_len = read_key(argv[5], expected_tag, sizeof expected_tag);
      if (expected_tag_len < 0) {
        error(EXIT_FAILURE, errno, "unable to read the tag from %s", argv[5]);
      }
      verification = true;
    case 5:
      counter = strtoul(argv[4], &endptr, 0);
      if (counter > UCHAR_MAX || argv[4][0] == '\0' || *endptr != '\0') {
        error(EXIT_FAILURE, errno, "'%s' is not a valid counter (0..255)\n",
              argv[4]);
      }
    case 4:
      message = argv[3];
    case 3:
      if (read_key(argv[2], peer_key, sizeof peer_key) != sizeof peer_key) {
        error(EXIT_FAILURE, errno, "unable to read the peer key from %s",
              argv[2]);
      }
      print_hex(stderr, "peer-key:   0x", peer_key, sizeof peer_key);
    case 2:
      if (read_key(argv[1], private_key, sizeof private_key) !=
          sizeof private_key) {
        if (errno != ENOENT) {
          error(EXIT_FAILURE, errno, "unable to read the private key from %s",
                argv[1]);
        }
        int fd = open(argv[1], O_WRONLY | O_EXCL | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1) {
          error(EXIT_FAILURE, errno, "unable to create a new file at %s",
                argv[1]);
        }
        if (glome_generate_key(private_key, public_key)) {
          error(EXIT_FAILURE, 0, "unable to generate a new key pair");
        }
        if (write(fd, private_key, sizeof private_key) != sizeof private_key) {
          error(EXIT_FAILURE, errno, "unable to write the private key to %s",
                argv[1]);
        }
        close(fd);
      }
      break;
    default:
      error(EXIT_FAILURE, 0, kUsage, argv[0], argv[0], argv[0]);
  }

  if (glome_derive_key(private_key, public_key)) {
    error(EXIT_FAILURE, 0, "unable to derive public key");
  }

  if (argc == 2) {  // key generation
    if (isatty(STDOUT_FILENO) == 1) {
      print_hex(stdout, NULL, public_key, sizeof public_key);
    } else {
      write(STDOUT_FILENO, public_key, sizeof public_key);
    }
    return EXIT_SUCCESS;
  }

  // Debug information
  print_hex(stderr, "public-key: 0x", public_key, sizeof public_key);
  fprintf(stderr, "message:   '%s'\n", message == NULL ? "" : message);
  fprintf(stderr, "counter:    %ld\n", counter);
  fprintf(stderr, "verify:     %d\n", verification);

  if (glome_tag(verification, counter, private_key, public_key, peer_key,
                (uint8_t *)message, message == NULL ? 0 : strlen(message),
                tag)) {
    error(EXIT_FAILURE, 0, "MAC tag generation failed");
  }

  if (argc == 6) {  // tag verification
    print_hex(stderr, "mac-tag:    0x", tag, sizeof tag);
    print_hex(stderr, "unverified: 0x", expected_tag, expected_tag_len);
    if (memcmp(expected_tag, tag, expected_tag_len) != 0) {
      error(EXIT_FAILURE, 0, "MAC tag verfication failed");
    }
  } else {  // tag generation
    print_hex(stdout, NULL, tag, sizeof tag);
  }

  return EXIT_SUCCESS;
}
