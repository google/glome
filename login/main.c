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

#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "login.h"
#include "ui.h"

static void handle_error(const char* error_tag) {
  if (error_tag != NULL) {
    errorf("\nError: %s\n", error_tag);
  }

  // Let's sleep for a bit in case the console gets cleared after login exits so
  // the user has a chance to see all the output.
  fflush(NULL);
  sleep(2);
}

int main(int argc, char* argv[]) {
  glome_login_config_t config = {0};

  // Parse arguments to initialize the config path.
  int r = parse_args(&config, argc, argv);
  if (r > 0) {
    return EXITCODE_USAGE;
  }
  if (r < 0) {
    handle_error("parse-args");
    return EXITCODE_PANIC;
  }

  // Reset config while preserving the config path.
  const char* config_path = config.config_path;
  default_config(&config);
  config.config_path = config_path;

  // Read configuration file.
  status_t status = glome_login_parse_config_file(&config);
  if (status != STATUS_OK) {
    handle_error(status);
    return EXITCODE_PANIC;
  }

  // Parse arguments again to override config values.
  r = parse_args(&config, argc, argv);
  if (r > 0) {
    return EXITCODE_USAGE;
  }
  if (r < 0) {
    handle_error("parse-args");
    return EXITCODE_PANIC;
  }

  const char* error_tag = NULL;
  int rc = login_run(&config, &error_tag);
  if (rc) {
    handle_error(error_tag);
  }
  return rc;
}
