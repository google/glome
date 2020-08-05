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

confuse_dep = dependency('libconfuse')

install_data(
  'example.cfg',
  rename : 'config',
  install_dir : join_paths(get_option('sysconfdir'), 'glome'))

login_lib = shared_library(
    'glome-login',
    [
        'base64.h',
        'crypto.c',
        'crypto.h',
        'lockdown.c',
        'lockdown.h',
        'login.c',
        'openssl/base64.c',
        'ui.c',
        'ui.h',
    ],
    dependencies : [openssl_dep, glib_dep],
    link_with : glome_lib,
    include_directories : glome_incdir,
    install : true, soversion : '0')

pkg.generate(login_lib,
  description : 'glome-login, an authentication system built upon GLOME')

glome_login = executable(
    'glome-login',
    [
        'main.c',
        'config.c',
        'config.h',
    ],
    dependencies : confuse_dep,
    link_with : login_lib,
    include_directories : glome_incdir,
    install : true,
    install_dir : get_option('sbindir'))

# TODO: Make tests compilation based on get_option('tests')
login_test = executable(
    'login_test', 'login_test.c',
    dependencies : [openssl_dep, glib_dep],
    link_with : [glome_lib, login_lib],
    include_directories : glome_incdir)
test('login test', login_test)

crypto_test = executable(
    'crypto_test', 'crypto_test.c',
    dependencies : [openssl_dep, glib_dep],
    link_with : [glome_lib, login_lib],
    include_directories : glome_incdir)
test('crypto test', crypto_test)

