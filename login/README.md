# glome-login

This binary implements the client side of the
[GLOME Login](../docs/glome-login.md) protocol. It is written to be a
replacement of login(1).

## Usage

 1. Create a configuration file, see [example.cfg](example.cfg).
 1. Try it out by running `glome-login -c glome.cfg -- root`

## Configuration

In order to reduce external dependencies, a custom parser is used
to read the configuration file. The parser supports a simplified
version of the INI syntax with the following limitations:

* Quoting and escaping is not supported.
* Comments are allowed only at the start of the line and can
  begin with either `#` or `;`.

## Installation

The installation is dependent on what system you are running.

### systemd

Create a override file for the getty instance e.g. in
`/etc/systemd/system/serial-getty@.service.d/glome.conf`.

```ini
[Service]
ExecStart=
ExecStart=-/sbin/agetty -l /usr/local/sbin/glome-login \
  -o '-- \\u' --keep-baud 115200,38400,9600 %I $TERM
```

Alternatively or for a normal VTY, use
`/etc/systemd/system/getty@.service.d/glome.conf`.

```ini
[Service]
ExecStart=
ExecStart=-/sbin/agetty -l /usr/local/sbin/glome-login \
  -o '-- \\u' --noclear %I $TERM
```

### PAM module

`pam_glome.so` library implements the PAM authentication module for the
[GLOME Login](../docs/glome-login.md) protocol.

1. Install the library into the system dependent location for PAM modules
   (for example `/lib/security/pam_glome.so`).
1. Enable and configure PAM module for a specific service (for example
   `/etc/pam.d/login`):

```
auth       requisite  pam_glome.so
```

PAM module supports the following options:

* `config_path=PATH` - location of the configuration file to parse (defaults to
  `/etc/glome/config`)
* `key=KEY` - use hex-encoded `KEY` as the service key (defaults to key
  from configuration file)
* `key_version=N` - use `N` for the service key version (defaults to key
  version from configuration file)
* `url_prefix=URL` - use given URL prefix (defaults to prefix from configuration
  file)
* `debug` - enable verbose logging
* `print_secrets` - enable logging of secrets (INSECURE!)
* `host_id=NAME` - use `NAME` as the host-id
* `ephemeral_key=KEY` - use hex-encoded `KEY` instead of the ephemeral
  secret key (INSECURE!)

## Troubleshooting

glome-login uses error tags to communicate errors on `stderr`.

The PAM module logs errors with `syslog`.

### no-service-key

This error means that `glome-login` could not figure out what service key to
use. This most likely means that you have not specified a service key in the
configuration file (by default `/etc/glome/config`).

## Docker

Dockerfile included in the repository creates a Docker image that can be used
to test `glome-login` and the PAM module.

### Building the Container

Docker image for GLOME needs to be built first using the following command:

```sh
docker build -t glome -f kokoro/docker/Dockerfile .
```

### Running the Container

Container is than started in the background with two TCP ports published to the
host:

```sh
container=$(docker run -d -p 2022:22 -p 2023:23 glome)
```

Once the container is running it is possible to login using `netcat` or
`socat`, for example:

```sh
socat tcp-connect:localhost:2023 file:`tty`,raw,echo=0
```

Regular SSH client can be used for testing the PAM module:

```sh
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p 2022 root@localhost
```

Authorization code required for GLOME Login can be obtained by running:

```sh
docker exec $container /usr/local/bin/glome login --key /usr/local/etc/glome/private.key https://glome.example.com/v1/...
```
