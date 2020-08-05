# GLOME-Go
**This is not an officially supported Google product.**

This repository contains a Golang implementation for the GLOME protocol. You can
find the library as well as the tests in the folder `glome`. 


## Go API

### Note
This API is Alpha. Thus, it might be subject to changes in the future.

### Example

In order for Alice and Bob to communicate, the first step would be to generate some
new keys:

```go
import (
        "glome" 
        "crypto/rand"
)

// Alice generates new random KeyPair
alicePub, alicePriv, err := glome.GenerateKeys(rand.Reader)
if err != nil { [...] }

// Bob generates Private Key from an existing byte array
b := [32]byte{0,2,...,7,6}
bobPriv := glome.PrivateKey(b)

// Bob could have as well generated the key from byte slice
s := b[:]
bobPriv, err := glome.PrivateKeyFromSlice(s)
if err != nil { [...] }

// Bob deduces public key
bobPub, err := bobPriv.Public()
if err != nil { [...] }
```

Suppose that Alice knows `bobPub` and wants to send Bob the message
`msg` and no other message have been shared before. Alice will need to generate 
a `Dialog`:

```go
d, err := alicePriv.Exchange(bobPub)
if err != nil { [...] }

firstTag := d.Tag(msg, 0)
secondTag := d.Tag(msg, 1)
```

And Alice will send Bob both `msg`, `firstTag` as well as Alice's public key.
On Bob ends he will need to do the following:

```go
d, err := bobPriv.Exchange(alicePub)
if err != nil { [...] }

valid := d.Check(tag, msg, 0)

if !valid {
    // Maybe someone is pretending to be Alice!
    // Return an error.
}
// do what you have to do 
```

### Documentation

For more information see the in-code documentation.

### Test

Tests module can be execute with `go test`.
