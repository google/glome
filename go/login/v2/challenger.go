package v2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/google/glome/go/glome"
)

// Challenger produces challenges that a Responder can respond to.
type Challenger struct {
	// PublicKey is the server's public key.
	//
	// This field must always be set.
	PublicKey *glome.PublicKey

	// The fields below are optional, their zero values work as expected.

	// MinResponseLength is the minimal length of a response string required for verification.
	//
	// Recommended and default setting of this field is 10 (see protocol documentation).
	MinResponseLength uint8

	// MessageTagPrefixLength is the number of error detection bytes added to the challenge.
	//
	// Setting this to non-zero allows to detect a mismatch between the public key used by the
	// client and the public key inferred by the server from index or public key prefix.
	MessageTagPrefixLength uint8

	// KeyIndex that the server uses to identify its private key.
	//
	// If unset, the challenge will be created with the public key prefix instead.
	KeyIndex *uint8

	// RNG generates ephemeral private keys for this Challenger.
	//
	// If unset, crypto/rand.Reader will be used.
	// WARNING: Don't set this field unless you know what you are doing!
	RNG io.Reader
}

// ClientChallenge is the internal representation of a challenge as it would be used on a client.
//
// ClientChallenge instances must be created by Challenger.Challenge()!
type ClientChallenge struct {
	d *glome.Dialog
	// The minimum length of an acceptable response.
	min uint8

	h *handshake
	m []byte
}

// Challenge creates a clientChallenge object for this message and the Challenger configuration.
func (c *Challenger) Challenge(msg *Message) (*ClientChallenge, error) {
	h := &handshake{}

	rng := c.RNG
	if rng == nil {
		rng = rand.Reader
	}
	publicKey, key, err := glome.GenerateKeys(rng)
	if err != nil {
		return nil, err
	}
	h.PublicKey = publicKey

	if c.PublicKey == nil {
		return nil, fmt.Errorf("need a public key")
	}

	if c.KeyIndex != nil {
		h.Index = *c.KeyIndex
	} else {
		h.Prefix = &c.PublicKey[glome.PublicKeySize-1]
	}

	minResponseSize := uint8(c.MinResponseLength)
	if minResponseSize == 0 {
		minResponseSize = 10
	}

	d, err := key.TruncatedExchange(c.PublicKey, glome.MinTagSize)
	if err != nil {
		return nil, err
	}

	encodedMsg := []byte(msg.Encode())
	if c.MessageTagPrefixLength > 0 {
		h.MessageTagPrefix = d.Tag(encodedMsg, 0)[:c.MessageTagPrefixLength]
	}

	return &ClientChallenge{h: h, d: d, m: encodedMsg, min: minResponseSize}, nil
}

// Encode encodes the challenge into its URI path represenation.
func (c *ClientChallenge) Encode() string {
	return strings.Join([]string{"v2", c.h.Encode(), string(c.m), ""}, "/")
}

// Verify a challenge response string.
func (c *ClientChallenge) Verify(s string) bool {
	// In order to accept truncated base64 data, we need to handle special cases:
	// - a single byte from an encoded triple can never decode correctly
	// - 32 byte encode with a trailing padding character, which makes RawURLEncoding unhappy.
	n := len(s)

	// We check the response size here so that we don't need to deal with length conversion between
	// Base64 and HMAC.
	if n < int(c.min) {
		return false
	}
	if n%4 == 1 || n == 44 {
		n--
	}
	tag, err := base64.RawURLEncoding.DecodeString(s[:n])
	if err != nil {
		return false
	}
	return c.d.Check(tag, c.m, 0)
}
