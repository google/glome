# glome-login

This binary implements the client side of the
[GLOME Login](../docs/glome-login.md) protocol. It is written to be a
replacement of login(1).

## Usage

 1. Create a configuration file, see [example.cfg](example.cfg).
 1. Try it out by running `glome-login -c glome.cfg -- root`

## Installation

The installation is dependent on what system you are running.

### systemd

Create a override file for the getty instance e.g. in
`/etc/systemd/system/serial-getty@.service.d/glome.conf`.

```
[Service]
ExecStart=
ExecStart=-/sbin/agetty -l /usr/local/sbin/glome-login \
  -o '-- \\u' --keep-baud 115200,38400,9600 %I $TERM
```

Alternatively or for a normal VTY, use
`/etc/systemd/system/getty@.service.d/glome.conf`.

```
[Service]
ExecStart=
ExecStart=-/sbin/agetty -l /usr/local/sbin/glome-login \
  -o '-- \\u' --noclear %I $TERM
```

## Troubleshooting

glome-login uses error tags to communicate errors.

### no-service-key

This error means that `glome-login` could not figure out what service key to
use. This most likely means that you have not specified a service key in the
configuration file (by default `/etc/glome/config`).
