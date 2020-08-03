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

#include "lockdown.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ui.h"

#define EXPECTED_NO_LOCKDOWN "0\n"
#define EXPECTED_LOCKDOWN "1\n"
#define EXPECTED_MAX_SIZE                                 \
  (sizeof EXPECTED_NO_LOCKDOWN > sizeof EXPECTED_LOCKDOWN \
       ? sizeof EXPECTED_NO_LOCKDOWN                      \
       : sizeof EXPECTED_LOCKDOWN)

int check_lockdown(const char* path) {
  FILE* fd;
  if (path == NULL || path[0] == '\0') {
    return LOCKDOWN_DISABLED;  // nothing to check
  }
  fd = fopen(path, "r");
  if (fd == NULL) {
    if (errno == ENOENT) {  // no lockdown file present
      return LOCKDOWN_DISABLED;
    }
    errorf("ERROR: opening %s failed: ", path);
    perror(NULL);
    return 2;
  }
  char buffer[EXPECTED_MAX_SIZE] = {0};
  size_t read_bytes = fread(buffer, sizeof(char), sizeof(buffer) - 1, fd);
  if (read_bytes != sizeof(buffer) - 1) {
    if (feof(fd) != 0) {
      errorf("ERROR: read %zu byte(s) from %s\n", read_bytes, path);
      return 3;
    }
    errorf("ERROR: error while reading %s: ", path);
    perror(NULL);
    return 4;
  }
  if (strncmp(buffer, EXPECTED_NO_LOCKDOWN, sizeof EXPECTED_NO_LOCKDOWN) == 0) {
    return LOCKDOWN_DISABLED;
  } else if (strncmp(buffer, EXPECTED_LOCKDOWN, sizeof EXPECTED_LOCKDOWN) ==
             0) {
    return LOCKDOWN_ENABLED;
  }
  // unexpected outcome
  errorf("ERROR: unexpected contents of lockdown file %s\n", path);
  return 5;
}
