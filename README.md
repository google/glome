# Generic Low Overhead Message Exchange (GLOME)

**This is not an officially supported Google product.**

Generic Low Overhead Message Exchange (GLOME) is a protocol providing secure
authentication and authorization for low dependency environments.

This repository consists of a number of components of the GLOME ecosystem.

Documentation:

 - [GLOME protocol](docs/protocol.md)
 - [GLOME Login protocol](docs/glome-login.md)

Core libraries:

 - [libglome](glome.h) *C*
 - [PyGLOME](python) *Python*
 - [jGLOME](java) *Java*
 - [GLOME-Go](go/glome) *Go*

Binaries:

 - [glome-cli](cli) *CLI utility for interacting with the core GLOME protocol*
 - [glome-login](login) *Replacement of login(1) implementing GLOME Login protocol*

In addition to the above components there are libraries planned for Java
and Go as well as a turnkey server for self-hosted GLOME login.

## Building

Building the GLOME library requires

 - Compiler conforming to C99 (e.g. gcc, clang)
 - Meson >=0.49.2
 - OpenSSL headers >=1.1.1
 - iniparser (for glome-login)
 - glib-2.0 (for tests)
 - libpam (for PAM module)

### Instructions

GLOME is built using [Meson](https://mesonbuild.com/). First, initialize the
Meson build directory. You only have to do this once per Meson configuration.

```shell
$ meson build
```

NOTE: You can customize the installation target by passing the `--prefix` flag.

Build the shared library `libglome.so` and the command line utility `glome`
inside the build root `./build`.

```shell
$ ninja -C build
```

Now run the tests.

```shell
$ meson test -C build
```

Install both the binary and the library into the configured prefix (the default
prefix is `/usr/local/`, which will require admin privileges).

```shell
$ meson install -C build
```

