% PAM_GLOME(8) GLOME Login PAM module manual

# NAME

pam_glome - PAM Authentication Module for GLOME Login protocol

# SYNOPSIS

**pam_glome.so** [config_path=*path*] [key=*hex_key*] [key_version=*n*]
[min_authcode_len=*n*] [prompt=*message*] [debug] [host_id=*name*]
[host_id_type=*type*] [print_secrets] [ephemeral_key=*hex_key*]

# DESCRIPTION

The **pam_glome** module implements the client-side authentication for the
**Generic Low-Overhead Message Exchange (GLOME)** Login protocol. It provides
cryptographic challenge-response authentication mechanism that can be used to
secure serial consoles or as a second factor for standard login services.

During the authentication process, the module displays a challenge URL. The
user then uses a GLOME-compatible client to generate an authorization code,
which they provide at the prompt.

The module reads settings from a configuration file (`/etc/glome/config` by
default) and allows specific settings to be overridden via PAM options.

# OPTIONS

For all options listed below, hyphens (**-**) and underscores (**\_**) can be
used interchangeably in the parameter names.

config_path=*path*
:   Specify the location of the GLOME configuration file.
    Defaults to `/etc/glome/config`.

key=*hex_key*
:   Use the provided hex-encoded string as the service key. This overrides
    any key specified in the configuration file.

key_version=*n*
:   Specify the version of the service key to use. This value is embedded in the
    challenge prefix to inform the server which private key to use for
    authorization.

min_authcode_len=*n*
:   Enforce a minimum required length for the authorization code. The default
    and minimum allowed value is 10.

prompt=*message*
:   Override the default challenge prompt displayed to the user.

debug
:   Enable more verbose log messages in syslog.

host_id=*name*
:   Set the host identifier used in the GLOME Login protocol. When unset, fully
    qualified local hostname is used. If the hostname cannot be determined, it
    falls back to the hardware product UUID from DMI.

host_id_type=*type*
:   Specify the type of the host identifier to use in the GLOME Login protocol.

print_secrets
:   Enable logging of secrets to syslog. **WARNING: This is insecure and
    should only be used for debugging.**

ephemeral_key=*hex_key*
:   Use the provided hex-encoded string as the ephemeral secret key instead
    of generating new key for each challenge. **WARNING: This is insecure and
    intended for testing purposes only.**

# MODULE TYPE PROVIDED

Only the **auth** module type is provided.

# RETURN VALUES

PAM_SUCCESS
:   The provided GLOME authorization code is valid for the given challenge.

PAM_AUTH_ERR
:   Authentication failed. This could be due to an incorrect GLOME authorization
    code or an error was encountered.

# EXAMPLES

To enable GLOME authentication as a mandatory module for the login service,
add the following line to `/etc/pam.d/login`:

- `auth required pam_glome.so`

To enable debug logging with a specific configuration file use:

- `auth required pam_glome.so debug config_path=/etc/glome/custom.cfg`

# SECURITY NOTES

The module includes a specific check for OpenSSH "fake password". When OpenSSH
is configured to disallow a login (for example, via `PermitRootLogin no`), it
may provide a decoy token to the PAM stack to prevent timing attacks.
**pam_glome** detects this token using a constant-time comparison and rejects
the attempt immediately.

# SEE ALSO

**glome-login**(1), **glome**(1).

GLOME source code and all documentation may be downloaded from
<https://github.com/google/glome>.
