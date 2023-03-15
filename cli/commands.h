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

#ifndef CLI_COMMANDS_H_
#define CLI_COMMANDS_H_

// Generates a new key and writes it to stdout.
int genkey(int argc, char **argv);

// Reads a private key from stdin and writes the corresponding public key to
// stdout.
int pubkey(int argc, char **argv);

// Tags a message and writes it to stdout.
int tag(int argc, char **argv);

// Returns 0 iff the tag could be verified.
int verify(int argc, char **argv);

// Generates a tag for a glome-login challenge and writes it to stdout.
int login(int argc, char **argv);

#endif  // CLI_COMMANDS_H_
