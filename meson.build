# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project('glome', 'c', license : 'Apache-2.0', version : '0.1')

pkg = import('pkgconfig')

sysconfdir = join_paths(get_option('prefix'), get_option('sysconfdir'))
add_project_arguments('-DSYSCONFDIR="' + sysconfdir + '"', language : 'c')

openssl_dep = dependency('openssl', version : '>=1.1')

glome_lib = shared_library('glome', 'glome.c', dependencies : openssl_dep,
  install : true, soversion : '0')
glome_incdir = include_directories('.')
pkg.generate(glome_lib,
  description : 'GLOME, the Generic Low Overhead Message Exchange')
install_headers('glome.h')

glome_cli = executable('glome', 'cli/main.c', link_with : glome_lib,
  install : true)

cli_test = find_program('cli/test.sh')
test('cli', cli_test,
  args : glome_cli,
  timeout : 120)
