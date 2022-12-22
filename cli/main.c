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
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "commands.h"
#include "glome.h"

#define GLOME_CLI_MAX_MESSAGE_LENGTH 4095

#define UNUSED(var) (void)(var)

static const char *kUsage =
    "Usage: \n"
    "  To generate a new keypair\n"
    "    umask 077\n"
    "    %s genkey | tee PRIVATE-KEY-FILE | %s pubkey >PUBLIC-KEY-FILE\n\n"
    "  To generate a tag:\n"
    "    %s tag --key PRIVATE-KEY-FILE --peer PEER-KEY-FILE "
    "[--counter COUNTER] <MESSAGE-FILE\n\n"
    "  To verify a tag:\n"
    "    %s verify --key PRIVATE-KEY-FILE --peer PEER-KEY-FILE --tag TAG "
    "[--counter COUNTER] <MESSAGE-FILE\n\n"
    "  To generate a tag for a glome-login URL path:\n"
    "    %s login --key PRIVATE-KEY-FILE /v1/AYUg8AmJMKdUdIt93LQ-91oNvzoN"
    "Jjga9OukqY6qm05q0PU=/my-server.local/shell/root/\n";

static int print_help(int argc, char **argv) {
  UNUSED(argc);
  UNUSED(argv);
  fprintf(stderr, kUsage, argv[0], argv[0], argv[0], argv[0], argv[0]);
  return EXIT_SUCCESS;
}

typedef int (*mainfunc)(int argc, char **argv);

struct cmd {
  const char *name;
  mainfunc run;
};

// cmds maps subcommand names to their implementation. The last entry with a
// NULL name is executed when the subcommand given by the user is not found.
static const struct cmd cmds[] = {
    {"genkey", &genkey}, {"pubkey", &pubkey}, {"tag", &tag},
    {"verify", &verify}, {"login", &login},   {NULL, &print_help},
};

int main(int argc, char **argv) {
  if (argc == 0) {
    fputs("called with empty argv\n", stderr);
    return EXIT_FAILURE;
  }
  if (argc < 2) {
    return print_help(argc, argv);
  }
  // Traverse the known subcommands until the requested subcommand is found, or
  // until we hit the catch-all without a name.
  const struct cmd *c = cmds;
  while (c->name && strcmp(c->name, argv[1])) {
    c++;
  }
  return c->run(argc, argv);
}
