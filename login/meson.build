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

login_lib = static_library(
    'glome-login',
    [
        'base64.h',
        'config.c',
        'config.h',
        'crypto.c',
        'crypto.h',
        'openssl/base64.c',
        'ui.c',
        'ui.h',
    ],
    dependencies : [openssl_dep],
    link_with : glome_lib,
    include_directories : glome_incdir,
    install : false)

pkg.generate(login_lib,
  description : 'glome-login, an authentication system built upon GLOME')

glome_login = executable(
    'glome-login', ['main.c', 'login.c'],
    dependencies : [openssl_dep],
    link_with : login_lib,
    include_directories : glome_incdir,
    install : true,
    install_dir : get_option('sbindir'))

if get_option('tests')
    login_test = executable(
        'login_test', ['login_test.c', 'login.c'],
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

    config_test = executable(
        'config_test', 'config_test.c',
        dependencies : [openssl_dep, glib_dep],
        link_with : [glome_lib, login_lib],
        include_directories : glome_incdir)
    test('config test', config_test, args: files('config_test.cfg'))
    test('config test with url-prefix', config_test, args: files('config_test_url-prefix.cfg'))
endif

if get_option('pam-glome')
    cc = meson.get_compiler('c')
    libpam = cc.find_library('pam')

    args = ['-DPAM_GLOME']
    pam_ext_present = cc.has_function('pam_syslog',
        dependencies: libpam,
        prefix: '#include <security/pam_ext.h>')
    if pam_ext_present
        args += ['-DHAVE_PAM_EXT']
    endif

    pam_glome = shared_library(
        'pam_glome', ['pam.c', 'login.c'],
        c_args : args,
        dependencies : [libpam, openssl_dep],
        link_with : [glome_lib, login_lib],
        include_directories : glome_incdir,
        name_prefix : '',
        install : true,
        install_dir : join_paths(get_option('libdir'), 'security'))

    if get_option('tests')
        libpamtest = dependency('libpamtest', required : false)
        if libpamtest.found()
            oldstyle_run_pamtest = cc.compiles('''#include <stddef.h>
            #include <libpamtest.h>
            void test() { run_pamtest(NULL, NULL, NULL, NULL); }
            ''',
                dependencies : [libpamtest])
            pam_test = executable(
                'pam_test', 'pam_test.c',
                dependencies : [libpamtest],
                c_args : oldstyle_run_pamtest ? '-DOLDSTYLE_RUN_PAMTEST' : [])
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
endif
