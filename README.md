# Generic Low Overhead Message Exchange (GLOME)

**GLOME Login** is a [challenge-response authentication mechanism](https://en.wikipedia.org/wiki/Challenge%E2%80%93response_authentication). It resembles [one-time authorization codes](https://en.wikipedia.org/wiki/One-time_password) (aka OTPs) but is different from [HOTP] and [TOTP] in the following ways:

- It is stateless (unlike [HOTP]).
- It does not depend on time (unlike [TOTP]).
- It does not require a predefined secret sharing (unlike [HOTP] and [TOTP]).

These properties make it a good choice for low dependency environments (e.g., devices with no persistent storage, source of entropy, or a real-time clock). It can be also useful for managing access to a large fleet of hosts where synchronising state or sharing a predefined secrets can be a challenge. 

GLOME Login can be easily integrated with existing systems through [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) (`lib_glome`) or through the a [login(1)](https://manpages.debian.org/testing/login/login.1.en.html) wrapper ([glome-login](login)).

[GLOME Login protocol](docs/glome-login.md) is is built on top of the [Generic Low Overhead Message Exchange (GLOME) protocol](docs/protocol.md).

[TOTP]: https://www.rfc-editor.org/rfc/rfc6238
[HOTP]: https://www.rfc-editor.org/rfc/rfc4226

## How does it work?

Let's imagine the following scenario:

Alice is a system engineer who got paged to investigate an unresponsive machine that happens to be located far away. She calls Bob, a datacenter technican with physical access to the machine.

Alice is authorized to access the machine but has no connectivity. Bob faces the the opposite problem, he can access the machine's serial port but does not have credentials to log in.

Alice is able to use GLOME Login to grant Bob one-time access to the machine. First, Bob connects to the machine over serial port and types `root` on the login prompt. It is then provided with a challenge that he forwards to Alice. The challenge contains information about the identity of accessed host and the requrested action (i.e., root shell acess). Alice verifies that the request is legitimate (e.g., the accessed host is indeed the one she's trying to diagnose), and uses [`glome` CLI](cli) to generate an authorization code. She forwards that authorization code to Bob who provides it as a challenge response.

The authorization succeeds and Bob is able to run diagnostic commands and share the results with Alice.

## Getting started

### Installation on the client host

These steps should be followed on the host you are planning to use to generate authorization codes (e.g., a laptop).

1. Follow [build](docs/build) to build the `glome` CLI binary.
1. Generate a key pair using the `glome` command. Note that if the `glome` command is not in your `$PATH`, you might need to provide a full path to the binary.
```
$ glome genkey | tee glome-private.key | glome pubkey | tee glome-public.key | xxd -c 32 -p
4242424242424242424242424242424242424242424242424242424242424242
```

The output of that command is the approver public key that will be used to configure the target host.


### Installation on the target host

1. Follow [instructions](login) to configure your host to use PAM module (recommended) or glome-login.
1. Edit the configuration file (by default located at `/etc/glome/config`) and replace the key value with the approver public key generated in the previous section.
```
$ cat /etc/glome/config
key=4242424242424242424242424242424242424242424242424242424242424242
key-version=1
```

### Usage

Try to log in to the target host. You should see the prompt with the challenge:

```
GLOME: v1/AU7U7GiFDG-ITgOh8K_ND9u41S3S-joGp7MAdhIp_rQt/myhost/shell/root/
Password: 
```

Use the `glome` CLI on the client host to obtain an authorization code:

```
$ glome --key glome-private.key login v1/AU7U7GiFDG-ITgOh8K_ND9u41S3S-joGp7MAdhIp_rQt/myhost/shell/root/
Tm90aGluZyB0byBzZWUgaGVyZSwgbW92ZSBhbG9uZy4K
```

Provide the generated authcode as a response to the challenge.


## Repository

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

 - [glome](cli) *Command-line interface for GLOME*
 - [glome-login](login) *Replacement of login(1) implementing GLOME Login protocol*

In addition to the above components there are libraries planned for Java
and Go as well as a turnkey server for self-hosted GLOME login.

## Building

Building the GLOME library requires

 - Compiler conforming to C99 (e.g. gcc, clang)
 - Meson >=0.49.2
 - OpenSSL headers >=1.1.1
 - glib-2.0 (for glome-login as well as tests)
 - libpam (for PAM module)

Alternatively, on systems with [Nix](https://nixos.org/), you can simply run `nix-shell` in the root directory of this repository.

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

## Disclaimer

**This is not an officially supported Google product.**
