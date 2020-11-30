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

package server

import (
	"fmt"
	"sync"

	"github.com/google/glome/go/glome"
)

// ErrInvalidKeyIndex denotes that provided index is invalid for a key. Only
// indexes in {0,...,127} are valid.
type ErrInvalidKeyIndex struct {
	Index uint8
}

func (e ErrInvalidKeyIndex) Error() string {
	return fmt.Sprintf("key index should be in {0,...,127}, found: %v", e.Index)
}

// ErrDuplicatedKeyIndex denotes that provided index is already in use, so no
// new keys can be assigned to it.
type ErrDuplicatedKeyIndex struct {
	Index uint8
}

func (e ErrDuplicatedKeyIndex) Error() string {
	return fmt.Sprintf("key index already in use, found: %v", e.Index)
}

// A PrivateKey represent a Private key for the login server. It is a pair composed of a private key
// and its pairing index.
type PrivateKey struct {
	Value glome.PrivateKey
	Index uint8
}

// A PublicKey represent a Service key for the login server. It is a pair composed of a public key
// and its pairing index.
type PublicKey struct {
	Value glome.PublicKey
	Index uint8
}

// KeyManager performs key maneger task in a concurrent-safe way. It allows for constant
// time search of keys by index. KeyManager is constructed with NewKeyManager function.
type KeyManager struct {
	indexToPriv map[uint8]glome.PrivateKey
	publicKeys  []PublicKey
	lock        sync.RWMutex
}

func (k *KeyManager) locklessAdd(key glome.PrivateKey, index uint8) error {
	if index > 127 {
		return ErrInvalidKeyIndex{Index: index}
	}
	if _, ok := k.indexToPriv[index]; ok {
		return ErrDuplicatedKeyIndex{Index: index}
	}

	pub, err := key.Public()
	if err != nil {
		return err
	}

	k.indexToPriv[index] = key
	k.publicKeys = append(k.publicKeys, PublicKey{Value: *pub, Index: index})
	return nil
}

// Add adds provided key and index to the key manager. Return ErrInvalidindex
// if index provided is not in {0,...,127} and ErrDuplicatedIndex if index
// provided was already in use.
func (k *KeyManager) Add(key glome.PrivateKey, index uint8) error {
	k.lock.Lock()
	defer k.lock.Unlock()
	return k.locklessAdd(key, index)
}

// Read returns the PrivateKey stored in the KeyManager for a index, or a
// zero-value PrivateKey if no PrivateKey is present. The ok result indicates
// whether value was found in the KeyManager.
func (k *KeyManager) Read(index uint8) (glome.PrivateKey, bool) {
	k.lock.RLock()
	defer k.lock.RUnlock()

	key, ok := k.indexToPriv[index]
	return key, ok
}

// DropAllReplace drops all stored keys and replace them with the new ones provided.
// This operation is done in a atomic way (no other call to the struct will be handled
// while DropAllReplace is).
func (k *KeyManager) DropAllReplace(keys []PrivateKey) error {
	k.lock.Lock()
	defer k.lock.Unlock()

	k.indexToPriv = make(map[uint8]glome.PrivateKey)

	for _, key := range keys {
		if err := k.locklessAdd(key.Value, key.Index); err != nil {
			return err
		}
	}
	return nil
}

// ServiceKeys returns a copy slice of the public keys being at use at this moment by
// the KeyManager.
func (k *KeyManager) ServiceKeys() []PublicKey {
	serviceKey := make([]PublicKey, len(k.publicKeys))
	copy(serviceKey, k.publicKeys)
	return serviceKey
}

// Return a function that implements key fetching. The function
// returns ErrInvalidKeyIndex if index is not in {0,...,127}, and nil
// if the provided index does not match any key.
func (k *KeyManager) keyFetcher() func(uint8) (*glome.PrivateKey, error) {
	return func(index uint8) (*glome.PrivateKey, error) {
		if index > 127 {
			return nil, ErrInvalidKeyIndex{Index: index}
		}

		key, found := k.Read(index)
		if !found {
			return nil, nil
		}

		return &key, nil
	}
}

// NewKeyManager returns a new key manager.
func NewKeyManager() *KeyManager {
	return &KeyManager{
		indexToPriv: make(map[uint8]glome.PrivateKey),
		publicKeys:  make([]PublicKey, 0),
	}
}
