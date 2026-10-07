# go/login/server

Package `server` is an HTTP server framework for the **GLOME Login server side**. It builds on top of [`go/login`](../) to provide a ready-to-use `http.Handler` that validates incoming GLOME Login challenge URLs, authorizes users, and returns authorization codes.

> **Note:** This API is Alpha and may be subject to breaking changes.

## Overview

In the GLOME Login flow, the *server* receives a challenge URL (forwarded by a human operator from a target machine), verifies the embedded handshake, checks whether the requesting user is authorized to perform the action, and responds with an authorization code.

This package handles the HTTP plumbing so you only need to supply:
1. A **key manager** with your service private keys.
2. An **authorizer** that decides whether a given `(user, host, action)` tuple is permitted.

## Package Layout

```
go/login/server/
├── server.go       # LoginServer, Authorizer interface, option functions
└── keymanager.go   # KeyManager, PrivateKey, PublicKey types
```

## Quick Start

```go
import (
    "net/http"
    "github.com/google/glome/go/login/server"
)

func main() {
    // 1. Create a key manager and load your service key(s).
    km := server.NewKeyManager()
    km.Add(myPrivateKey, 1 /* key index 0-127 */)

    // 2. Define an authorization policy.
    authz := server.AuthorizerFunc(func(user, hostID, hostIDType, action string) (bool, error) {
        // Allow root shell on any host for all authenticated users.
        return action == "shell/root" && user != "", nil
    })

    // 3. Build the server.
    srv, err := server.NewLoginServer(authz,
        server.ResponseLen(16),         // shorter auth codes (optional)
        server.UserHeader("x-user-id"), // custom header name (optional)
    )
    if err != nil {
        panic(err)
    }
    srv.Keys = km

    // 4. Register as a standard http.Handler.
    http.ListenAndServe(":8080", srv)
}
```

## Key Types

### `LoginServer`

The central type. Implements `http.Handler`.

```go
type LoginServer struct {
    Keys *KeyManager
    // ...
}
```

**Endpoints served by `ServeHTTP`:**

| Path | Behaviour |
|------|-----------|
| `/` | Returns a list of the server's service public keys (so clients can configure target machines). |
| `/v1/<handshake>/<message>/` | Validates the GLOME Login URL, runs the authorizer, and returns the authorization code or an error. |

**Constructor:**

```go
srv, err := server.NewLoginServer(authorizer, ...options)
```

**Options** (functional-options pattern):

| Option | Default | Description |
|--------|---------|-------------|
| `ResponseLen(n uint8)` | `44` (32 bytes, base64) | Length of the returned auth code in base64 characters. Must be in `[1, 44]`. |
| `UserHeader(name string)` | `"authenticated-user"` | HTTP request header from which the authenticated username is read. |

**Updating the authorizer at runtime:**

```go
srv.Authorizer(newAuthorizerImpl) // concurrency-safe swap
```

### `KeyManager`

A concurrency-safe store for the server's private keys, indexed by an integer ID in `[0, 127]`.

```go
km := server.NewKeyManager()

// Add a key.
err := km.Add(privateKey, 1)

// Atomically replace all keys (e.g. after a key rotation).
err = km.DropAllReplace([]server.PrivateKey{
    {Value: newPrivKey, Index: 2},
})

// Look up a key by index.
privKey, ok := km.Read(2)

// List all current public keys (for publishing to clients).
pubKeys := km.ServiceKeys()
```

Key indexes must be unique and in `[0, 127]`. The `LoginServer` uses `KeyManager` to resolve the key ID embedded in an incoming challenge URL.

### `Authorizer` interface

You implement this to encode your authorization policy:

```go
type Authorizer interface {
    GrantLogin(user, hostID, hostIDType, action string) (bool, error)
}
```

For simple cases, `AuthorizerFunc` lets you use a plain function:

```go
authz := server.AuthorizerFunc(func(user, hostID, hostIDType, action string) (bool, error) {
    return myPolicyCheck(user, hostID, action)
})
```

**Contract for implementors:**
- An empty `user` string means no user identity could be extracted from the request (treat as unauthenticated).
- An empty `action` is a valid input; decide whether to allow it explicitly.
- Both `hostID` and `hostIDType` may be empty strings.
- The returned `bool` is acted upon even when a non-nil `error` is also returned.

### Key and error types

| Type | Description |
|------|-------------|
| `PrivateKey` | A `{Value glome.PrivateKey, Index uint8}` pair |
| `PublicKey` | A `{Value glome.PublicKey, Index uint8}` pair |
| `ErrInvalidKeyIndex` | Key index is outside `[0, 127]` |
| `ErrDuplicatedKeyIndex` | Key index is already registered |
| `ErrInvalidResponseLen` | Response length is outside `[1, 44]` |

## Running the Tests

```sh
cd go
go test ./login/server/...
```

## Related Packages

- [`go/login`](../) — core protocol types (`Client`, `Server`, `URLResponse`)
- [`go/glome`](../../glome) — GLOME cryptographic primitives
- [GLOME Login protocol spec](../../../docs/glome-login.md)
