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

This document describes version 2 of GLOME Login, see also
[RFD001](rfd/001.md) for a rationale of the protocol elements.

## Implementation

The current version of the GLOME login protocol uses the
[standard GLOME variant](protocol.md#variants).
Counters are set to constant `0` since only a single set of messages
is exchanged.

The protocol assumes that the client (i.e., the machine being accessed),
knows the public key of the server. Required elements of the protocol are:

* A host identifier that uniquely identifies the client.
* An action on the client that needs to be authorized by the server.

These optional elements can provide additional information to the server:

* A host identifier type, among which the host identifier is unique.
* A server key index, to tell the server which private key to use.
* A message tag prefix, to allow error detection on the server side.

The client combines these elements into a challenge string, which the server
validates and responds to with a GLOME tag. GLOME Login challenges are suitable
for embedding into a URL.

### Challenge request format

The GLOME login client generates the challenge in the form:

```abnf
challenge = "v2/" handshake-segment "/" message "/"

handshake-segment = Base64_urlsafe( prefix client-public-key [message-tag-prefix] )

message = host-segment "/" action-segment
host-segment = EscapePathSegment( [hostid-type ":"] hostid )
action-segment = EscapePathSegment(action)
```

The individual elements of this specification and the encoding functions are
described in the subsections below.

#### Challenge Transport Considerations

The client should then output the resulting challenge prefixed by the
configured prompt. In practice, that configurable prefix can be used to present
the challenge as an URL which can be used to submit the challenge to a GLOME
serve.

The challenge must always end in a `/` to make it easy for the GLOME login
server to detect truncated requests and reject those early. Without the
trailing slash requirement the request will still likely look correct but may
result in an invalid request being signed causing confusion for the operator.

#### Host ID

The client identifies itself as a named host, using the `hostid` field. This ID
often is a fully qualified domain name, so adhering to domain name restrictions
when choosing host ids is a good idea. However, these restrictions are not
enforced by this protocol, but the host id should not need to be encoded for
inclusion as a URL path segment, and it should not include a `:` character, as
that is used to separate type and id.

Providing a host id type is optional, but can help with the interpretation of
the host id itself. It is subject to the same encoding considerations as the id
itself. If no host id type is provided, host ids should be interpreted as host
names.

#### Action

The `<action>` field represents the action being authorized and should not
be ambiguous in a way that affects security. The format of the action is left
up to the implementer to decide but it has to take into account these points:

  * The `<action>` should be suitable for embedding in a URL path element
    (see also the section on encodings below).
  * The `<action>` should be human readable and easy to understand
    both as part of the URL and stand alone.

Good examples:

  * `shell=root` starts a shell as the given user, root in this case.
  * `reboot` reboots the target.
  * `show-logs=httpd` outputs debug logs for the `httpd` application.

Bad examples:

  * `exec` executes a command.
    * This is bad because it does not specify which command is being executed.
  * `exec=cm0gLWZyIC8=` executes a given command (Base64 encoded).
    * This is not human readable.
  * `shell` starts a shell as an user-provided but undisclosed user.
    * This is bad if there exists ambiguity on which user the shell will launch
      as. E.g. if the system is hard-coded to only allow login as root, this
      example is OK - otherwise not.
  * `shell/root`
    * This used to be the recommended format in v1, but it creates ambiguity
      between the host part and the action part and will thus be
      percent-encoded, which harms legibility.

#### Handshake

The prefix is one byte, of which the most significant bit disambiguates the use
of the low 7 bit. If the MSB is set, the low bits are interpreted as a 7 bit
integer, which the server should interpret as the index of the key its supposed
to use. If the MSB is not set, the entire byte represents the most significant
byte of the public key that the server is supposed to use.

The public key corresponding to the client's ephemeral key for this challenge
is appended as raw 32 bytes, in the encoding specified in RFC 7748.

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

For an efficient base64-encoding, the raw message tag prefix should have a
length divisible by 3.

#### Encodings

In order to safely embed the handshake and message in a URL, the individual
protocol elements need to be encoded.

The handshake is encoded using URL-safe Base64, as specified in
<https://www.rfc-editor.org/rfc/rfc4648#section-5>.

The message consists of two path elements, which are encoded individually,
using the percent-encoding scheme specified in
<https://url.spec.whatwg.org/#percent-encoded-bytes>, and then joined by a `/`
character.

### Response format

The response is a Base64 URL-safe (base64url) MAC tag computed over the
`<message>` field as provided by the client. The GLOME login client can accept a
shortened tag (prefix) to reduce the message cost. Ephemeral keys are valid only
for one attempt, thus the brute forcing is severely limited, and can be further
slowed down by introducing an artificial delay before comparing the tags.

### Test vectors

Test vectors that conform to this specification are defined in
[login-v2-test-vectors.yaml](login-v2-test-vectors.yaml). They describe two
parties, Alice and Bob, who run through a GLOME Login challenge-response
workflow. In these scenarios, Alice is always the client and Bob the server.

## Alternatives

The GLOME protocol is based on the assumption that the cost of transmitting
messages in the server-to-client direction is higher than in the opposite
direction.

If that is not the case, then using an existing proven signature scheme (e.g,
[Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519)) is recommended.
