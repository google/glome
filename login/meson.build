confuse_dep = dependency('libconfuse')

install_data(
  'example.cfg',
  rename : 'config',
  install_dir : get_option('sysconfdir'))

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

