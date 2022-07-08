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

project('glome', 'c', license : 'Apache-2.0', version : '0.1',
  default_options : ['c_std=c99', 'warning_level=3', 'werror=true'])

pkg = import('pkgconfig')

sysconfdir = join_paths(get_option('prefix'), get_option('sysconfdir'))
add_project_arguments('-DSYSCONFDIR="' + sysconfdir + '"', language : 'c')
add_project_arguments('-D_POSIX_C_SOURCE=200809L', language : 'c')

openssl_dep = dependency('openssl', version : '>=1.1')

glome_lib = shared_library('glome', 'glome.c', dependencies : openssl_dep,
  install : true, soversion : '0')
glome_incdir = include_directories('.')
pkg.generate(glome_lib,
  description : 'GLOME, the Generic Low Overhead Message Exchange')
install_headers('glome.h')

if get_option('tests')
    glib_dep = dependency('glib-2.0')
    glome_test = executable('glome_test', 'glome_test.c', dependencies : glib_dep,
      link_with : glome_lib, include_directories : glome_incdir)
    test('glome', glome_test)
endif

subdir('login')

if get_option('glome-cli')
    subdir('cli')
endif
