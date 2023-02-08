# GLOME login protocol

## Introduction

GLOME login is first application of the [GLOME protocol](protocol.md). It is
used to authorize serial console access to Linux machines.

To achieve that, a client program called `glome-login` is executed by getty (or
a similar process) instead of the conventional `/sbin/login`. Instead of
prompting the user for the password, it generates an URL that points at the
authorization server and contains the GLOME handshake information and the action
requested by the operator. The operator follows that URL and upon successful
authentication and authorization, the server provides the operator with an
authorization code response that needs to be returned to `glome-login`.

If the authorization code matches the one calculated internally by
`glome-login`, the user is authorized and glome-login executes the requested
action - e.g. providing the login shell or rebooting the machine.

## Implementation

The current version of the GLOME login protocol uses the
[standard GLOME variant](protocol.md#variants).
Counters are set to constant `0` since only a single set of messages
is exchanged.

*   GLOME handshake information and tags are encoded as Base64-encoded URLs or
    "base64url"
    [[RFC4648 section 5](https://tools.ietf.org/html/rfc4648#section-5)].
*   Initial message from the GLOME login client to the server contains the
    context required for authorization (i.e. host identity, requested action).
*   The authorization context is sent in clear for easier debuggability and
    reducing the likelihood of human errors (e.g. incomplete URL copy and
    paste).
*   Server's public key can be identified by:
    *   7-bit service key identifier and message tag prefix (of any
        length, including 0).
    *   7-bit service key prefix and message tag prefix (of any length,
        including 0),
*   Using a message tag prefix provides an additional protection against channel
    errors (e.g. caused by operator errors).
*   The message sent from the GLOME login client to the server contains the context required for authorization (i.e. host identity, requested action).
*   In this protocol the client and the server sign identical messages.
    the client to the server, and therefore is omitted.

### Challenge request format

The GLOME login client generates the challenge in the form of an URL:

```
<prompt>v<V>/<glome-handshake>[/<message>]/

glome-handshake := base64url(
    <prefix-type>
    <prefix7>
    <eph-key>
    [<prefixN>]
  )

message := [<hostid-type>:]<hostid>[/<action>]
```

where <fields> have the following meanings:

| Field           |      Length | Description                                      |
| :-------------- | ----------: | :----------------------------------------------- |
| prompt          | arbitrary   |                                                  |
| V               | 1 byte      | URL format version. Currently always 1.          |
| prefix-type     | 1 bits      | Determines the meaning of (prefix7; prefixN) fields: <br><ul><li>0: (service key indicator; message tag prefix)</li><li>1: reserved</li></ul>Service key indicator is either index, or if no index found will be matched<br>with the public key (to be administrator configurable) |
| prefix7         | 7 bits      | Purpose determined by prefix-type.               |
| eph-key         | 32 bytes    | Client's public key (ephemeral).                 |
| prefixN         | 0..32 bytes | Purpose determined by prefix-type, right now message tag prefix. |
| hostid-type     | 0..n bytes  | Type of identity; `hostname` if not set          |
| hostid          | 1..n bytes  | Identity of the target (e.g. hostname, serial number, etc.) |
| action          | 0..n bytes  | Action that is being authorized (e.g. reboot, shell).<br>Both parties should agree what the default action is if not set. |

The client should then output the resulting challenge as a fully-qualified URL,
with the server portion set to the GLOME server able to sign responses for this
request and the protocol preferably set to HTTPS.

The URL should always end in a `/` to make it easy for the GLOME login server to
detect truncated requests and reject those early. Without the trailing slash
requirement the request will likely look correct and may result in an invalid
request being signed causing confusion for the operator.

#### Action

The `<action>` field represents the action being authorized and should not
be ambiguous in a way that affects security. The format of the action is left
up to the implementer to decide but it has to take into account these points:

  * The `<action>` needs to be suitable for embedding in a URL.
  * The `<action>` should be human readable and easy to understand
    both as part of the URL and stand alone.

Good examples:

  * `shell/root` starts a shell as the given user, root in this case.
  * `reboot` reboots the target.
  * `show-logs/httpd` outputs debug logs for the HTTPD application.

Bad examples:

  * `exec` executes a command.
    * This is bad because it does not specify which command is being executed.
  * `exec/cm0gLWZyIC8=` executes a given command (Base64 encoded).
    * This is not human readable.
  * `shell` starts a shell as an user-provided but undisclosed user.
    * This is bad if there exists ambiguity on which user the shell will launch
      as. E.g. if the system is hard-coded to only allow login as root, this
      example is OK - otherwise not.

#### URL construction

Care must be taken to ensure that the URL outputted by the GLOME login client
is a well-formed URL.

A GLOME login client should make sure to format the URL as per
[[RFC 3986 Section 2.4](https://tools.ietf.org/html/rfc3986#section-2.4)]. The
intent should be to maximize the human readability of the URL.

**Example:** If the GLOME login server is running on https://glome.example.com/
and the challenge is `/v1/AAAAAAA.../serial:ab@!c/action/` the resulting URL
should be presented as
https://glome.example.com/v1/AAAAAAA.../serial:ab@!c/action/.
The important lesson from this example is that `serial:ab@!c` is **not** encoded
using percent encoding as there is no reason to and would sacrifice human
readability needlessly.

Finally it is recommended to verify that commonly used terminal emulators
correctly identify the whole URL when outputted.

#### Message tag prefix

The message tag prefix is calculated by the client as the MAC tag over the
`<message>` field. The client can choose to include as much of the tag as it
prefers.

The server can verify the integrity of the message doing the same calculation
and performing a prefix comparison of the expected tag and the received
message tag prefix.

The message tag prefix does not offer any additional security properties unless
the server enforces its inclusion. However, the message tag prefix is still
useful to detect accidental message corruption. It can also be used to
resolve ambiguity in which service key was used by the client.

### Response format

The response is a Base64 URL-safe (base64url) MAC tag computed over the
`<message>` field as provided by the client. The GLOME login client can accept a
shortened tag (prefix) to reduce the message cost. Ephemeral keys are valid only
for one attempt, thus the brute forcing is severely limited, and can be further
slowed down by introducing an artificial delay before comparing the tags.

### Test vectors

These are some example test cases that can be used to verify an implementation
of the GLOME login protocol.  Octet strings (keys and tags) are represented in
hexadecimal encoding, message counters in their decimal represenation and
messages and strings in ASCII encoding.

[Ka]: https://render.githubusercontent.com/render/math?math=K_a
[Ka']: https://render.githubusercontent.com/render/math?math=K_a^%27
[Kb]: https://render.githubusercontent.com/render/math?math=K_b
[Kb']: https://render.githubusercontent.com/render/math?math=K_b^%27
[Ks]: https://render.githubusercontent.com/render/math?math=K_s
[Mn]: https://render.githubusercontent.com/render/math?math=M_n
[T]: https://render.githubusercontent.com/render/math?math=T

For in-depth definition of the GLOME variables, see the [protocol](protocol.md)
specification. In summary note that
![K_x'](https://render.githubusercontent.com/render/math?math=K_x^%27) is the
private key and
![K_x](https://render.githubusercontent.com/render/math?math=K_x) is the
associated public key.

#### Vector 1

Login request using service key index 1, message tag prefix length of 16 bits,
and response tag length of 60 bits.

|               Variable | Value                                                              |
|-----------------------:|:-------------------------------------------------------------------|
| ![K_a'][Ka']           | `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a` |
| ![K_b'][Kb']           | `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb` |
| `prefix-type`          | `0`                                                                |
| `prefix7`              | `1`                                                                |
| `eph-key` (![K_a][Ka]) | `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a` |
| `hostid-type`          | Omitted                                                            |
| `hostid`               | `my-server.local`                                                  |
| `action`               | `shell/root`                                                       |
|                        |                                                                    |
| ![K_b][Kb]             | `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f` |
| ![K_s][Ks]             | `4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742` |
| ![M_n][Mn]             | `my-server.local/shell/root`                                       |
| `prefixN`              | `d0f59d0b17cb155a1b9cd2b5cdea3a17f37a200e95e3651af2c88e1c5fc8108e` |
| ![T][T]                | `9721ee687b827249dbe6c244ba459216cf01d525012163025df358eb87c89059` |
|                        |                                                                    |
| Request URL            | `/v1/AYUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q0PU=/my-server.local/shell/root/` |
| Response token         | `lyHuaHuCck`                                                       |

#### Vector 2

Login request using service key prefix, no message tag prefix, and full response tag.

|               Variable | Value                                                              |
|-----------------------:|:-------------------------------------------------------------------|
| ![K_a'][Ka']           | `fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead` |
| ![K_b'][Kb']           | `b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d` |
| `prefix-type`          | `0`                                                                |
| `prefix7`              | `0x51`                                                             |
| `eph-key` (![K_a][Ka]) | `872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376` |
| `hostid-type`          | `serial-number`                                                    |
| `hostid`               | `1234567890=ABCDFGH/#?`                                            |
| `action`               | `reboot`                                                           |
|                        |                                                                    |
| ![K_b][Kb]             | `d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647` |
| ![K_s][Ks]             | `4b1ee05fcd2ae53ebe4c9ec94915cb057109389a2aa415f26986bddebf379d67` |
| ![M_n][Mn]             | `serial-number:1234567890=ABCDFGH/#?/reboot`                       |
| `prefixN`              | `dff5aae753a8bdce06038a20adcdb26c7be19cb6bd05a7850fae542f4af29720` |
| ![T][T]                | `a7c33f0542a3ef35c154cd8995084d605c6ce09f83cf1440a6cf3765a343aae6` |
|                        |                                                                    |
| Request URL            | `/v1/UYcvQ1u4uJ0OOtYqouURB07hleHDnvaogAFBi-ZW48N2/serial-number:1234567890=ABCDFGH%2F%23%3F/reboot/` |
| Response token         | `p8M_BUKj7zXBVM2JlQhNYFxs4J-DzxRAps83ZaNDquY=`                     |

## Alternatives

The GLOME protocol is based on the assumption that the cost of transmitting
messages in the server-to-client direction is higher than in the opposite
direction.

If that is not the case, then using an existing proven signature scheme (e.g,
[Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519)) is recommended.
