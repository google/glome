# glome-login

This binary implements the client side of the
[GLOME Login](../docs/glome-login.md) protocol. It is written to be a
replacement of login(1).

## Usage

 1. Create a configuration file, see [example.cfg](example.cfg).
 1. Try it out by running `glome-login -c glome.cfg -- root`

## Lockdown

Lockdown mode allows you to restrict logins on machines.
It is similar to nologin(5), except that it applies to all users
that are trying to lock in.

Example usage of lockdown is that you can allow logins
only on broken machines, e.g. by having some sort of health checker
output the expected token in the lockdown file. Another example
is that you may want to only allow access until the machine has
been handed off to production, at which point you can flip the
contents of the lockdown file.

If lockdown is enabled by passing `-i` and the referenced lockdown file exists,
a login will only be initiated if the lockdown file contains exactly the correct
byte sequence expected for a disabled lockdown.

By default the expected file contents is `0\n`.
The expected lockdown file contents in case of lockdown is `1\n` and
any other values will throw an error. glome-login will
assume lockdown is in effect as long as it cannot positively confirm
the expected contents of the lockdown file or the lockdown file does
not exist.

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
