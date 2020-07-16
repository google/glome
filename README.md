# Generic Low Overhead Message Exchange (GLOME)

**This is not an officially supported Google product.**

Generic Low Overhead Message Exchange (GLOME) is a protocol providing secure
authentication and authorization for low dependency environments.

## C API

### Requirements

-   C standard library (C99)
-   OpenSSL >=1.1.1

### Example

Generating two key pairs:

```shell
$ glome Alice >Alice.pub
$ glome Bob >Bob.pub
```

Alice calculates a tag and send it together with message and counter to Bob:

```shell
$ tag=$(glome Alice Bob.pub "Hello world!" 0)
peer-key:   0xbe106dba769f75f215f29b3b5e5e84c792a9d5562a26c9f7e19915c73bb45413
public-key: 0xe2e97a41a60fd6a3c5de511862671f97e9f8e0d657044cac783e5119eeecae06
message:   'Hello world!'
counter:    0
verify:     0

$ echo "${tag?}"
2b4dc85086e41a5c616301d904ac2dd942f2d71a56985a5be252b5bbca30bdfa
```

Bob can verify that the tag matches:

```shell
$ glome Bob Alice.pub "Hello world!" 0 "${tag?}"
peer-key:   0xe2e97a41a60fd6a3c5de511862671f97e9f8e0d657044cac783e5119eeecae06
public-key: 0xbe106dba769f75f215f29b3b5e5e84c792a9d5562a26c9f7e19915c73bb45413
message:   'Hello world!'
counter:    0
verify:     1
mac-tag:    0x2b4dc85086e41a5c616301d904ac2dd942f2d71a56985a5be252b5bbca30bdfa
unverified: 0x2b4dc85086e41a5c616301d904ac2dd942f2d71a56985a5be252b5bbca30bdfa

$ echo $?
0
```

Both parties can agree to shorten the tag to reduce the protocol overhead:

```shell
$ glome Bob Alice.pub "Hello world!" 0 "${tag:0:12}"
peer-key:   0xe2e97a41a60fd6a3c5de511862671f97e9f8e0d657044cac783e5119eeecae06
public-key: 0xbe106dba769f75f215f29b3b5e5e84c792a9d5562a26c9f7e19915c73bb45413
message:   'Hello world!'
counter:    0
verify:     1
mac-tag:    0x2b4dc85086e41a5c616301d904ac2dd942f2d71a56985a5be252b5bbca30bdfa
unverified: 0x2b4dc85086e41a5c616301d90

$ echo $?
0
```

## Building

Building the GLOME library requires

-   Compiler conforming to C99 (e.g. gcc, clang)
-   Meson >=0.49.2
-   OpenSSL headers >=1.1.1

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

