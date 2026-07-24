# go/login

Package `login` implements the **client and server sides of the GLOME Login protocol** in Go. It builds on top of the [`glome`](../glome) package to handle URL construction, handshake parsing, tag verification, and authorization code validation as described in the [GLOME Login protocol spec](../../docs/glome-login.md).

> **Note:** This API is Alpha and may be subject to breaking changes.

## Overview

GLOME Login is a challenge-response authentication mechanism. A client (e.g. a machine at a serial console) generates a URL encoding a *handshake* and a *message* (host identity + requested action). An operator forwards this URL to a GLOME Login server, which validates the request and returns an authorization code. The client verifies the code and grants access if it matches.

This package provides Go types for both sides of that exchange:

| Role   | Type     | Responsibility                                                    |
|--------|----------|-------------------------------------------------------------------|
| Client | `Client` | Build the challenge URL, validate the server's authorization code |
| Server | `Server` | Parse an incoming challenge URL, verify the client's tag          |

## Package Layout

```
go/login/
├── login.go        # Core types: Client, Server, URLResponse, Message, Handshake
└── server/         # Higher-level HTTP server framework (see go/login/server)
```

## Key Types

### `Message`

Encodes what is being authorized: a target host and an action.

```go
type Message struct {
    HostIDType string // optional type qualifier (e.g. "serial", "hostname")
    HostID     string // identity of the target host
    Action     string // action being requested (e.g. "shell/root")
}
```

`Message.Construct(esc bool)` serializes this to the wire format `[<hostid-type>:]<hostid>[/<action>]`, with optional URL-escaping.

### `Handshake`

Contains the cryptographic material exchanged in the URL path.

```go
type Handshake struct {
    Prefix           byte           // encodes the server key ID (or its lower 7 bits)
    UserKey          glome.PublicKey // client's ephemeral public key
    MessageTagPrefix []byte          // prefix of the tag computed over the Message
}
```

### `URLResponse`

Represents a fully constructed GLOME Login URL. Created by either `NewResponse` (server-side) or internally by `Client.Construct`.

```go
type URLResponse struct {
    V             byte      // URL format version (currently 1)
    HandshakeInfo Handshake
    Msg           Message
    // unexported: dialog, sendingKey
}
```

Useful methods:
- `Tag(len uint) []byte` — compute the GLOME tag over the message (used by the server to produce an auth code).
- `EncToken() string` — base64url-encoded response token (the authorization code to return to the client).
- `ValidateAuthCode(tag []byte) bool` — check whether a received tag is correct.
- `String() string` — render the full URL string.

### `Client`

Implements the **client side** of the protocol (e.g. embedded in `glome-login`).

```go
client := login.NewClient(serverPublicKey, userPrivateKey, serverKeyID, tagLen)

// Build the challenge URL to display to the operator
url, err := client.Construct(1, "", "myhost", "shell/root")

// After receiving the authorization code from the operator:
valid, err := client.ValidateAuthCode(receivedTag)
```

### `Server`

Implements the **server side** of the protocol. Requires a `KeyFetcher` callback to look up private keys by version ID.

```go
srv := login.Server{
    KeyFetcher: func(id uint8) (*glome.PrivateKey, error) {
        return keyStore.Lookup(id)
    },
}

response, err := srv.ParseURLResponse(incomingURL)
if err != nil {
    // handle: ErrInvalidURLFormat, ErrServerKeyNotFound, ErrIncorrectTag, ...
}

// Send the authorization code back to the operator:
authCode := response.EncToken()
```

`ParseURLResponse` validates:
1. The URL is well-formed (returns `ErrInvalidURLFormat` otherwise).
2. The server key corresponding to the handshake prefix exists (returns `ErrServerKeyNotFound` otherwise).
3. The client's embedded tag is valid (returns `ErrIncorrectTag` otherwise).

## Error Types

| Error                   | Meaning                                                  |
|-------------------------|----------------------------------------------------------|
| `ErrInvalidURLFormat`   | The URL does not conform to the GLOME Login URL format   |
| `ErrServerKeyNotFound`  | No server private key matches the prefix in the URL      |
| `ErrVersionNotSupported`| The URL format version `V` is not supported              |
| `ErrInvalidHandshakeLen`| The handshake segment is too short                       |
| `ErrInvalidPrefixType`  | The prefix type byte is invalid                          |
| `ErrIncorrectTag`       | The client's embedded tag failed verification            |
| `ErrResponseNotInitialized` | `ValidateAuthCode` called before `Construct`         |

## Running the Tests

```sh
cd go
go test ./login/...
```

## Related Packages

- [`go/glome`](../glome) — core GLOME cryptographic primitives (key generation, tag computation)
- [`go/login/server`](./server) — HTTP server framework built on top of this package
- [`login/`](../../login) — C implementation of `glome-login` (the `login(1)` replacement)
- [GLOME Login protocol spec](../../docs/glome-login.md)
