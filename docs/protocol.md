# GLOME Protocol

Generic Low-Overhead Message Exchange

> :information_source: **NOTE**: GLOME provides a solution to a fairly niche
> problem. If the following constraints don't apply in your case, you might be
> better off using established signature schemes (e.g.
> [EdDSA](https://en.wikipedia.org/wiki/EdDSA)).

## Introduction

GLOME combines ephemeral-static key exchange (e.g.
[X25519](https://en.wikipedia.org/wiki/Curve25519)) between two parties and uses
that to enable exchanging authenticated and integrity-protected messages using a
truncated tag (e.g. truncated [HMAC](https://en.wikipedia.org/wiki/HMAC)).

Ephemeral-static key exchange indicates that only one side can authenticate
itself through the key agreement, and in case of GLOME it is the server side.
Clients are not automatically authenticated since they are using ephemeral keys.

The protocol is designed to keep its overhead to minimum, assuming that sending
a message is expensive, and allows the parties to trade some security for
reduced overhead by operating on truncated HMAC tags.

## Real world applications

An example of a real-world scenario fitting the description above is authorizing
a human operator to access a device with the following constraints:

*   The device does not have a network connectivity (e.g. due to a failure or
    by design).
*   The device does not have a synchronized time (e.g. no real-time clock).
*   The device does not store any secrets (e.g. all its storage is easily
    readable by an adversary).
*   The device accepts input from a human operator via a very low-bandwidth
    device (e.g. a keyboard).
*   The device provides output to a human operator (e.g. via display).

With the constraints above, the operator effectively provides a low-bandwidth
channel for the device and the authorization server to communicate by passing
the messages back and forth. While there are ways to increase the bandwidth from
the device to the operator (e.g. via
[matrix codes](https://en.wikipedia.org/wiki/Barcode#Matrix_\(2D\)_barcodes)),
we must assume that the opposite direction requires the operator to type the
message manually on the keyboard, so minimizing the protocol overhead in that
direction is crucial.

To address this problem, the [GLOME login protocol](glome-login.md) based on
GLOME was invented.

## Caveats

*   GLOME does not protect confidentiality of exchanged messages. This is not a
    technical limitation (given that the protocol already performs a key
    exchange) but avoiding introducing unnecessary complexity. This decision can
    be revised in future revisions of this protocol, once there is a compelling
    use case to provide this.

*   The server is unable to authenticate the client just using GLOME due to the
    usage of ephemeral keys. A protocol built on top of GLOME should implement
    its own client authentication (if necessary).

## Protocol details

Alice and Bob want to exchange messages over an expensive untrusted channel,
i.e.:

*   The channel can be actively MITM-ed.
*   Cost-per-byte and cost-per-message are relatively high.
*   The cost function can be asymmetrical, i.e., the cost can be higher in one
    direction.

Alice and Bob can choose to lower the cost (i.e., the overhead) by accepting
weaker security.

Alice knows Bob's public key.

The protocol consists of an ephemeral-static Diffie-Hellman key exchange, and
uses the established shared secret to calculate MAC over combined payloads.

Alice wants to send a payload
![M_a](https://render.githubusercontent.com/render/math?math=M_a) to Bob. Alice
knows Bob's public key
![K_b](https://render.githubusercontent.com/render/math?math=K_b).

### Handshake

The handshake derives two MAC keys, one for each direction of communication,
from a shared secret that is established using a Diffie-Hellman key exchange.

Key derivation operations are only described in brief.
For full reference, see
[RFC 7748 Section 6.1](https://tools.ietf.org/html/rfc7748#section-6).

#### Alice

1.  Alice generates an ephemeral private key
    ![K_a'](https://render.githubusercontent.com/render/math?math=K_a^%27).
1.  Alice computes the corresponding public key
    ![K_a](https://render.githubusercontent.com/render/math?math=K_a) from
    ![K_a'](https://render.githubusercontent.com/render/math?math=K_a^%27).
1.  Alice uses
    ![K_a'](https://render.githubusercontent.com/render/math?math=K_a^%27) and
    Bob's public key
    ![K_b](https://render.githubusercontent.com/render/math?math=K_b) to derive
    the shared secret
    ![K_s](https://render.githubusercontent.com/render/math?math=K_s).
1.  Alice uses
    ![K_a](https://render.githubusercontent.com/render/math?math=K_a),
    ![K_b](https://render.githubusercontent.com/render/math?math=K_b) and
    ![K_s](https://render.githubusercontent.com/render/math?math=K_s) to
    construct MAC keys:
    1.  For messages from Alice to Bob
        ![K_{ab}](https://render.githubusercontent.com/render/math?math=K_%7Bab%7D):
        ![K_s || K_b || K_a](https://render.githubusercontent.com/render/math?math=K_s+||+K_b+||+K_a).
    1.  For messages from Bob to Alice
        ![K_{ba}](https://render.githubusercontent.com/render/math?math=K_%7Bba%7D):
        ![K_s || K_a || K_b](https://render.githubusercontent.com/render/math?math=K_s+||+K_a+||+K_b).
1.  At this point Alice can forget
    ![K_a'](https://render.githubusercontent.com/render/math?math=K_a^%27) and
    ![K_s](https://render.githubusercontent.com/render/math?math=K_s) so they
    cannot be accidentally reused.
1.  Alice sends
    ![K_a](https://render.githubusercontent.com/render/math?math=K_a) and
    indicates which
    ![K_b](https://render.githubusercontent.com/render/math?math=K_b) was used
    to Bob.

#### Bob

1.  Bob receives
    ![K_a](https://render.githubusercontent.com/render/math?math=K_a) and an
    indication of which
    ![K_b](https://render.githubusercontent.com/render/math?math=K_b) to be
    used.
1.  Bob uses the corresponding private key
    ![K_b'](https://render.githubusercontent.com/render/math?math=K_b^%27) and
    ![K_a](https://render.githubusercontent.com/render/math?math=K_a) to derive
    the shared secret
    ![K_s](https://render.githubusercontent.com/render/math?math=K_s).
1.  Bob computes the MAC keys
    ![K_{ab}](https://render.githubusercontent.com/render/math?math=K_%7Bab%7D)
    and
    ![K_{ba}](https://render.githubusercontent.com/render/math?math=K_%7Bba%7D)
    in the same way as Alice did.

### Exchanging messages

To prevent replay attacks, Alice and Bob need to maintain a pair of counters:
![N_{ab}](https://render.githubusercontent.com/render/math?math=N_%7Bab%7D) and
![N_{ba}](https://render.githubusercontent.com/render/math?math=N_%7Bba%7D).
Each zero-indexed counter represents the number of messages sent in a given
direction.

Once the handshake is complete, Alice and Bob can send messages
![M_n](https://render.githubusercontent.com/render/math?math=M_n) to each other
by computing a tag
![T](https://render.githubusercontent.com/render/math?math=T) over
![N_x || M_n](https://render.githubusercontent.com/render/math?math=N_x+||+M_n)
using key ![K_x](https://render.githubusercontent.com/render/math?math=K_x) and
incrementing ![N_x](https://render.githubusercontent.com/render/math?math=N_x).
![x](https://render.githubusercontent.com/render/math?math=x) is either
![ab](https://render.githubusercontent.com/render/math?math=ab) or
![ba](https://render.githubusercontent.com/render/math?math=ba), depending on
the direction of the message.

Upon receiving a message, the other party verifies its authenticity by repeating
the tag calculation and comparing the result (in constant-time) with the
received tag.

### Variants

There is currently only one variant of the protocol defined. This variant uses:

*   Curve25519 keys
    (![K_a](https://render.githubusercontent.com/render/math?math=K_a),
    ![K_a'](https://render.githubusercontent.com/render/math?math=K_a^%27),
    ![K_b](https://render.githubusercontent.com/render/math?math=K_b),
    ![K_b'](https://render.githubusercontent.com/render/math?math=K_b^%27)).
*   X25519 to derive the shared secret
    ![K_s](https://render.githubusercontent.com/render/math?math=K_s).
*   HMAC-SHA256 to calculate the message tag.
*   Unsigned 8-bit counters (0..255).

While the use of 8-bit counters limits the number of messages exchanged between
the parties, it is likely to be sufficient given the constraints that warrant
the usage of the protocol.

### Optional optimizations

*   To reduce the overhead at the cost of security, parties can truncate the
    exchanged tags and compare only prefixes of an acceptable length.
*   To reduce the number of messages exchanged, Alice can combine the initial
    handshake with sending the first message.
*   Sending the tag in the first message sent from Alice to Bob is not
    security-relevant since it does not authenticate the message as Alice uses
    ephemeral keys. It might be useful to detect accidental errors and for Bob
    to disambiguate between his multiple key pairs (more on that below).
*   The indication of Bob's public key
    (![K_b](https://render.githubusercontent.com/render/math?math=K_b)) can be
    done in different ways, each leading to varying degrees of communication
    overhead:
    1.  Specifying a truncated version of Bob's public key.
        *   The truncation can cause ambiguity if it matches multiple of Bob's
            keys.
    1.  Specifying a key identifier, e.g. the key's serial number.
        *   Requires pre-agreeing to key identifiers between both parties.
    1.  By including an (optionally truncated) tag over the message sent
        together with the handshake.
        *   This can cause ambiguity, if Bob discovers that multiple key pairs
            produce the same (truncated) tag.
    1.  If Bob has only one key, there is no need to indicate which one is being
        used.
        *   Not recommended, as this makes any key rotation difficult.

### Future improvements

*   Given that the protocol already establishes a shared secret between Alice
    and Bob, it could be used to encrypt the exchanged messages. We decided not
    to add it at this point to keep the protocol simpler.
*   The protocol could be extended to support multi-party settings (i.e., a
    client exchanging messages with multiple servers at the same time).

### Test vectors

These are some example test cases that can be used to verify an implementation
of the GLOME protocol. Octet strings (keys and tags) are represented in
hexadecimal encoding, message counters in their decimal represenation and
messages in ASCII encoding.

[Ka]: https://render.githubusercontent.com/render/math?math=K_a
[Ka']: https://render.githubusercontent.com/render/math?math=K_a^%27
[Kb]: https://render.githubusercontent.com/render/math?math=K_b
[Kb']: https://render.githubusercontent.com/render/math?math=K_b^%27
[Ks]: https://render.githubusercontent.com/render/math?math=K_s
[Nab]: https://render.githubusercontent.com/render/math?math=N_%7Bab%7D
[Nba]: https://render.githubusercontent.com/render/math?math=N_%7Bba%7D
[Mn]: https://render.githubusercontent.com/render/math?math=M_n
[T]: https://render.githubusercontent.com/render/math?math=T

#### Vector 1

Message from Alice to Bob.

| Variable       | Value                                                              |
|---------------:|:-------------------------------------------------------------------|
| ![K_a'][Ka']   | `77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a` |
| ![K_b'][Kb']   | `5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb` |
| ![N_{ab}][Nab] | `0`                                                                |
| ![M_n][Mn]     | `The quick brown fox`                                              |
|                |                                                                    |
| ![K_a][Ka]     | `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a` |
| ![K_b][Kb]     | `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f` |
| ![K_s][Ks]     | `4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742` |
|                |                                                                    |
| ![T][T]        | `9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3` |

#### Vector 2

Message from Bob to Alice.

| Variable       | Value                                                              |
|---------------:|:-------------------------------------------------------------------|
| ![K_a'][Ka']   | `fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead` |
| ![K_b'][Kb']   | `b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d` |
| ![N_{ba}][Nba] | `100`                                                              |
| ![M_n][Mn]     | `The quick brown fox`                                              |
|                |                                                                    |
| ![K_a][Ka]     | `872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376` |
| ![K_b][Kb]     | `d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647` |
| ![K_s][Ks]     | `4b1ee05fcd2ae53ebe4c9ec94915cb057109389a2aa415f26986bddebf379d67` |
|                |                                                                    |
| ![T][T]        | `06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277` |

### Reference implementation

The reference implementation consists of a glome binary that implements the
following operations.

#### Key pair generation

```
$ glome keygen <secret-key>
```

If `<secret-key>` does not exist, the private key is generated and written to
`<secret-key>`. Otherwise it reads the secret key from `<secret-key>`.

The tool prints out the corresponding public key to stdout (hex-encoded).

#### HMAC tag computation

```
$ glome tag <secret-key> <peer-key> [<message> [<counter>]]
```

Prints the hex-encoded tag over `<message>` (defaults to empty) with the counter
set to `<counter>` (defaults to 0).

#### HMAC tag verification

```
$ glome verify <secret-key> <peer-key> <tag> [<message> [<counter>]]
```

Verifies that the provided tag matches the expected tag over message `<message>`
with the counter set to `<counter>` as produced by peer using `<peer-key>`.

The tool exits with 0 on success, 1 on failure (tag mismatch).
