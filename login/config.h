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

#ifndef GLOME_LOGIN_CONFIG_H_
#define GLOME_LOGIN_CONFIG_H_

#include "ui.h"

// parse_config_file parses the configuration file and fills the given config
// struct with the data. The default config file is used in case no explicit
// config file has been provided, however in this case failed attempts to read
// the default config file will be ignored.
int parse_config_file(login_config_t* config);

#endif  // GLOME_LOGIN_CONFIG_H_
