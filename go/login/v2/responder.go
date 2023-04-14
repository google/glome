package v2

import (
	"encoding/base64"
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
			return nil, fmt.Errorf("invalid key index: %d", i)
		}
		pk, err := k.Public()
		if err != nil {
			return nil, fmt.Errorf("invalid key at index %d: %v", i, err)
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
		return nil, fmt.Errorf("format error")
	}
	if s[:len(versionPrefix)] != versionPrefix {
		return nil, fmt.Errorf("incompatible version")
	}
	s = strings.TrimPrefix(s, versionPrefix)
	s = strings.TrimSuffix(s, "/")

	subs := strings.SplitN(s, "/", 2)
	if len(subs) != 2 {
		return nil, fmt.Errorf("format error")
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
		return nil, fmt.Errorf("key not found")
	}
	d, err := key.TruncatedExchange(h.PublicKey, 1)
	if err != nil {
		return nil, err
	}

	if len(h.MessageTagPrefix) > 0 && !d.Check(h.MessageTagPrefix, encodedMessage, 0) {
		return nil, fmt.Errorf("message tag prefix did not match")
	}

	tag := d.Tag(encodedMessage, 0)
	return &ServerChallenge{
		Message:  m,
		Response: base64.URLEncoding.EncodeToString(tag),
	}, nil
}
