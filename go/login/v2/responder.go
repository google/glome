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
			return nil, &InvalidIndexError{i}
		}
		pk, err := k.Public()
		if err != nil {
			return nil, errors.Join(&InvalidKeyError{i}, err)
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
		return nil, ErrChallengeTooShort
	}
	if s[:len(versionPrefix)] != versionPrefix {
		return nil, ErrIncompatibleVersion
	}
	s = strings.TrimPrefix(s, versionPrefix)
	s = strings.TrimSuffix(s, "/")

	subs := strings.SplitN(s, "/", 2)
	if len(subs) != 2 {
		return nil, ErrNumPathSegments
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
		return nil, &KeyNotFoundError{h}
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

// TODO: document and test

type InvalidIndexError struct {
	Idx uint8
}

func (e *InvalidIndexError) Error() string {
	return fmt.Sprintf("key index %d is not in range [0; 127]", e.Idx)
}

type InvalidKeyError struct {
	Idx uint8
}

func (e *InvalidKeyError) Error() string {
	return fmt.Sprintf("invalid private key at index %d", e.Idx)
}

type KeyNotFoundError struct {
	h *handshake
}

func (e *KeyNotFoundError) Error() string {
	if e.h.Prefix != nil {
		return fmt.Sprintf("no key found with prefix 0x%02x", *e.h.Prefix)
	}
	return fmt.Sprintf("no key found with index %d", e.h.Index)
}

var ErrChallengeTooShort = errors.New("TODO")
var ErrIncompatibleVersion = fmt.Errorf("incompatible challenge version: expected %q", versionPrefix)
var ErrNumPathSegments = errors.New("challenge format error: wrong number of path segments")
var ErrTagPrefixMismatch = errors.New("message tag prefix did not match")
