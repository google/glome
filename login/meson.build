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

install_data(
  'example.cfg',
  rename : 'config',
  install_dir : join_paths(get_option('sysconfdir'), 'glome'))

iniparser_dep = meson.get_compiler('c').find_library('iniparser')

login_lib = static_library(
    'glome-login',
    [
        'base64.h',
        'config.c',
        'config.h',
        'crypto.c',
        'crypto.h',
        'login.c',
        'openssl/base64.c',
        'ui.c',
        'ui.h',
    ],
    dependencies : [openssl_dep, iniparser_dep],
    link_with : glome_lib,
    include_directories : glome_incdir,
    install : false)

pkg.generate(login_lib,
  description : 'glome-login, an authentication system built upon GLOME')

glome_login = executable(
    'glome-login', 'main.c',
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

if get_option('pam-glome')
    cc = meson.get_compiler('c')
    libpam = cc.find_library('pam')
    pam_glome = shared_library(
        'pam_glome', 'pam.c',
        dependencies : [libpam, openssl_dep],
        link_with : [glome_lib, login_lib],
        include_directories : glome_incdir,
        name_prefix : '',
        install : true,
        install_dir : join_paths(get_option('libdir'), 'security'))

    libpamtest = dependency('libpamtest', required : false)
    if libpamtest.found()
        pam_test = executable(
            'pam_test', 'pam_test.c',
            dependencies : [libpamtest])
        custom_target('pam_service',
            build_by_default : true, output : [ 'pam_service' ],
            command : [ 'mkdir', '@OUTPUT@' ])
        test('pam test', pam_test,
            env: [ 'LD_PRELOAD=libpam_wrapper.so', 'PAM_WRAPPER=1',
                'PAM_WRAPPER_SERVICE_DIR=' +
                join_paths(meson.build_root(), 'login', 'pam_service'),
                'PAM_GLOME=' +
                join_paths(meson.build_root(), 'login', 'pam_glome.so') ])
    endif
endif
