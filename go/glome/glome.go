// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package glome implements GLOME protocol.
package glome

import (
	"fmt"
	"io"

	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

const (
	// PrivateKeySize is the size of a PrivateKey in bytes.
	PrivateKeySize = 32
	// PublicKeySize is the size of a PublicKey in bytes.
	PublicKeySize = 32
	// MaxTagSize is the maximum size allowed for a Tag
	MaxTagSize = 32
	// MinTagSize is the minimum size allowed for a Tag
	MinTagSize = 1
)

var (
	// ErrInvalidPublicKey denotes that a slice that intend to be a public key is not of desired length
	ErrInvalidPublicKey = fmt.Errorf("invalid public key - byte slice len is not %d", PublicKeySize)
	// ErrInvalidPrivateKey denotes that a slice that intend to be a private key is not of desired length
	ErrInvalidPrivateKey = fmt.Errorf("invalid private key - byte slice len is not %d", PrivateKeySize)
	// ErrInvalidTagSize denotes that provided integer is not suitable to be minPeerTagSize
	ErrInvalidTagSize = fmt.Errorf("invalid tag size - minPeerTagSize must be in range %d-%d",
		MinTagSize, MaxTagSize)
	// ErrInvalidReader denotes that library failed to read PrivateKeySize bytes from given Reader.
	ErrInvalidReader = fmt.Errorf("invalid reader - failed to read %d bytes", PrivateKeySize)
)

// PublicKey is the type of GLOME public Keys.
//
// It can be initialized either by casting a [PublicKeySize]byte array or from a byte
// slice with the PublicKeyFromSlice function.
// Examples:
// - Generate Public Key as existing byte array
//       b := [32]byte{0,2,...,7,6}
//       p := glome.PublicKey(b)
//
// - Generate from byte slice
//       s := b[:]
//       p, err := glome.PublicKeyFromSlice(s)
//       if err != nil { [...] }
//
// - Read from File
//       p, err := ioutil.ReadFile(filename)
//       if err != nil { [...] }
//       priv, err := glome.PublicKeyFromSlice(p)
//       if err != nil { [...] }
type PublicKey [PublicKeySize]byte

// PublicKeyFromSlice generates a PublicKey object from slice. Return ErrInvalidPublicKey
// if slice's length is not PublicKeySize.
func PublicKeyFromSlice(b []byte) (*PublicKey, error) {
	if len(b) != PublicKeySize {
		return nil, ErrInvalidPublicKey
	}

	var p PublicKey
	copy(p[:], b)
	return &p, nil
}

// PrivateKey is the type of GLOME public keys.
//
// It can be initialized either by casting a [PrivateKeySize]byte array or from a byte
// slice with the PrivateKeyFromSlice function.
//
// Examples:
// - Generate Private Key as existing byte array:
//       b := [32]byte{0,2,...,7,6}
//       p := glome.PrivateKey(b)
//
// - Generate from byte slice:
//       s := b[:]
//       p, err := glome.PrivateKeyFromSlice(s)
//       if err != nil { [...] }
//
// - Read from File:
//       p, err := ioutil.ReadFile(filename)
//       if err != nil { [...] }
//       priv, err := glome.PrivateKeyFromSlice(p)
//       if err != nil { [...] }
type PrivateKey [PrivateKeySize]byte

// Public returns the PublicKey corresponding to priv.
func (priv *PrivateKey) Public() (*PublicKey, error) {
	slice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	p, _ := PublicKeyFromSlice(slice)
	return p, nil
}

// Exchange generates a Dialog struct. It performs GLOME handshake, and stores create
// a Dialog from the user to the peer. Sets minPeerTagSize as MaxTagSize.
func (priv *PrivateKey) Exchange(peer *PublicKey) (*Dialog, error) {
	s, err := curve25519.X25519(priv[:], peer[:])
	if err != nil {
		return nil, err
	}

	public, err := priv.Public()
	if err != nil {
		return nil, err
	}

	return &Dialog{shared: s, User: *public, Peer: *peer, minPeerTagSize: MaxTagSize}, nil
}

// TruncatedExchange generates a Dialog struct. It performs GLOME handshake,
// and stores create a Dialog from the user to the peer. Sets param m as minPeerTagSize.
func (priv *PrivateKey) TruncatedExchange(peer *PublicKey, m uint) (*Dialog, error) {
	if m == 0 || m > MaxTagSize {
		return nil, ErrInvalidTagSize
	}

	d, err := priv.Exchange(peer)
	if err != nil {
		return nil, err
	}

	d.minPeerTagSize = m
	return d, nil
}

// PrivateKeyFromSlice generates a private key from a slice. Fail if len of
// slice is not PrivateKeySize
func PrivateKeyFromSlice(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}

	var p PrivateKey
	copy(p[:], b)
	return &p, nil
}

// GenerateKeys generates a public/private key pair using entropy from rand.
func GenerateKeys(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	b := make([]byte, PrivateKeySize)
	n, err := rand.Read(b)
	if err != nil {
		return nil, nil, err
	}
	if n != PrivateKeySize {
		return nil, nil, ErrInvalidReader
	}

	priv, err := PrivateKeyFromSlice(b)
	if err != nil {
		return nil, nil, err
	}

	pub, err := priv.Public()
	if err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

// Dialog allow tag managing functionalities for GLOME protocol.
//
// Has to be generated with the methods Exchange or TruncatedExchange or Private key.
// For example:
//       pubKey, privKey, err := glome.GenerateKeys(rand.Reader)
//       if err != nil { [...] }
//       ex, err := privkey.Exchange(peerKey)
//
// If TruncatedExchange is selected, minPeerTagSize can be different to MaxTagSize. See
// documentation in method Check for more information on truncation.
type Dialog struct {
	shared         []byte
	User           PublicKey // User's Public key
	Peer           PublicKey // Peer's Public key
	minPeerTagSize uint      // Minimun Tag size allowed.
}

func (d *Dialog) sendingKey() []byte {
	return append(d.shared[:], append(d.Peer[:], d.User[:]...)...)
}

func (d *Dialog) receivingKey() []byte {
	return append(d.shared[:], append(d.User[:], d.Peer[:]...)...)
}

// Generates a tag matching some provided message, counter and password.
func generateTag(msg []byte, counter uint8, password []byte) []byte {
	h := hmac.New(sha256.New, password)
	h.Write([]byte{counter})
	h.Write(msg)
	return h.Sum(nil)
}

// Tag generates a tag matching some provided message and counter.
// This tag is generated following GLOME protocol specification
// in the context of a communication from the users to theirs peers.
func (d *Dialog) Tag(msg []byte, counter uint8) []byte {
	return generateTag(msg, counter, d.sendingKey())
}

// Check method checks if a tag matches some provided message and counter.
// The method generates the matching tag following GLOME protocol
// specification in the context of a communication from the users'
// peers to the users and then is compared with the tag provided.
//
// For the tag to be accepted it has to be equal in all its length
// to the correct tag. Also, its length must be at least MinPeerTagLength
// and always smaller than MaxTagSize.
func (d *Dialog) Check(tag []byte, msg []byte, counter uint8) bool {
	var prefixSize uint
	switch {
	case uint(len(tag)) < d.minPeerTagSize:
		prefixSize = d.minPeerTagSize
	case uint(len(tag)) > MaxTagSize:
		prefixSize = MaxTagSize
	default:
		prefixSize = uint(len(tag))
	}

	want := generateTag(msg, counter, d.receivingKey())[:prefixSize]
	return hmac.Equal(want, tag)
}
