package v2

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/glome/go/glome"
)

const versionPrefix = "v2/"

// Responder can parse challenges and create responses.
//
// Instances of Responder must be created with NewResponder().
type Responder struct {
	keysByIndex  map[uint8]*glome.PrivateKey
	keysByPrefix map[byte]*glome.PrivateKey
}

// NewResponder creates a Responder that uses the given private keys to respond
// to challenges.
func NewResponder(keys map[uint8]*glome.PrivateKey) (*Responder, error) {
	r := &Responder{
		keysByIndex:  make(map[uint8]*glome.PrivateKey),
		keysByPrefix: make(map[byte]*glome.PrivateKey),
	}
	for i, k := range keys {
		if i >= 1<<7 {
			return nil, fmt.Errorf("key index %d is not in range [0; 127]", i)
		}
		pk, err := k.Public()
		if err != nil {
			return nil, fmt.Errorf("invalid private key at index %d: %w", i, err)
		}
		r.keysByIndex[i] = k
		// We _could_ validate that prefixes are unique here, but we choose not to.
		r.keysByPrefix[pk[glome.PublicKeySize-1]] = k
	}
	return r, nil
}

// ServerChallenge contains the parsed Message from a challenge and an
// appropriate response.
//
// The Response must only be used after verifying the message content!
//
// Instances of ServerChallenge should be created by Responder.Accept().
type ServerChallenge struct {
	Message  *Message
	Response string
}

// Accept an encoded challenge and produce a response.
func (r *Responder) Accept(encodedChallenge string) (*ServerChallenge, error) {
	s := strings.TrimPrefix(encodedChallenge, "/")
	if len(s) < len(versionPrefix) {
		return nil, errors.New("challenge format error: too short")
	}
	if s[:len(versionPrefix)] != versionPrefix {
		return nil, fmt.Errorf("challenge version incompatible: expected %q, got %q", versionPrefix, s[:len(versionPrefix)])
	}
	s = strings.TrimPrefix(s, versionPrefix)
	s = strings.TrimSuffix(s, "/")

	subs := strings.SplitN(s, "/", 2)
	if len(subs) != 2 {
		return nil, errors.New("challenge format error: wrong number of path segments")
	}
	h, err := decodeHandshake(subs[0])
	if err != nil {
		return nil, err
	}

	encodedMessage := []byte(subs[1])
	m, err := decodeMessage(subs[1])
	if err != nil {
		return nil, err
	}

	var key *glome.PrivateKey
	ok := false
	if h.Prefix != nil {
		key, ok = r.keysByPrefix[*h.Prefix]
	} else {
		key, ok = r.keysByIndex[h.Index]
	}
	if !ok {
		return nil, &keyNotFoundError{h}
	}

	d, err := key.TruncatedExchange(h.PublicKey, 1)
	if err != nil {
		return nil, err
	}

	if len(h.MessageTagPrefix) > 0 && !d.Check(h.MessageTagPrefix, encodedMessage, 0) {
		return nil, ErrTagPrefixMismatch
	}

	tag := d.Tag(encodedMessage, 0)
	return &ServerChallenge{
		Message:  m,
		Response: base64.URLEncoding.EncodeToString(tag),
	}, nil
}

type keyNotFoundError struct {
	h *handshake
}

func (e *keyNotFoundError) Error() string {
	if e.h.Prefix != nil {
		return fmt.Sprintf("no key found with prefix 0x%02x", *e.h.Prefix)
	}
	return fmt.Sprintf("no key found with index %d", e.h.Index)
}

// ErrTagPrefixMismatch is returned when a tag prefix is included in the
// challenge, but it does not verify with the chosen key. This means that the
// public key chosen based on handshake information is not the one the client
// expected.
var ErrTagPrefixMismatch = errors.New("message tag prefix did not match")
