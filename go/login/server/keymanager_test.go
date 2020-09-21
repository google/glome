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
	"reflect"
	"testing"

	"github.com/google/glome/go/glome"
)

func Contains(list []PublicKey, pub PublicKey) bool {
	for _, b := range list {
		if b == pub {
			return true
		}
	}
	return false
}

func TestKeyAdd(t *testing.T) {
	for name, k := range []struct {
		priv  glome.PrivateKey
		index uint8
	}{
		{
			priv:  glome.PrivateKey([32]byte{}),
			index: 0,
		}, {
			priv: glome.PrivateKey([32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				1, 1}),
			index: 1,
		}, {
			priv: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
				192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
				67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
			index: 2,
		},
	} {
		manager := NewKeyManager()

		if err := manager.Add(k.priv, k.index); err != nil {
			t.Fatalf("test %v, unexpected error: %v ", name, err.Error())
		}

		readKey, found := manager.Read(k.index)
		if !found {
			t.Errorf("test %v: No private key %v was added in index %v",
				name, k.priv, k.index)
		}

		if readKey != k.priv {
			t.Errorf("test %v: private key %v was not added in index %v",
				name, k.priv, k.index)
		}

		pub, err := k.priv.Public()
		if err != nil {
			t.Fatalf("test %v, unexpected error: %v ", name, err.Error())
		}

		if !Contains(manager.publicKeys, PublicKey{Value: *pub, Index: k.index}) {
			t.Errorf("test %v: public key %v was not added in index %v",
				name, pub, k.index)
		}
	}
}

func TestKeyAddExceptions(t *testing.T) {
	type input struct {
		manager *KeyManager
		priv    glome.PrivateKey
		index   uint8
	}

	// PreloadManager is manager for test 2
	preloadManager := NewKeyManager()
	preloadManager.Add(glome.PrivateKey([32]byte{}), 0)

	for name, k := range []struct {
		in   input
		want error
	}{
		{
			in: input{
				manager: NewKeyManager(),
				priv:    glome.PrivateKey([32]byte{}),
				index:   0,
			},
			want: nil,
		}, {
			in: input{
				manager: preloadManager,
				priv:    glome.PrivateKey([32]byte{}),
				index:   0,
			},
			want: ErrDuplicatedKeyIndex{Index: 0},
		}, {
			in: input{
				manager: NewKeyManager(),
				priv:    glome.PrivateKey([32]byte{}),
				index:   129,
			},
			want: ErrInvalidKeyIndex{Index: 129},
		},
	} {
		if err := k.in.manager.Add(k.in.priv, k.in.index); err != k.want {
			t.Errorf("test %v failed to raises wanted exception on input %#v; got %#v, want %#v",
				name, k.in, err, k.want)
		}
	}
}

func TestKeyRead(t *testing.T) {
	type input struct {
		priv  glome.PrivateKey
		index uint8
	}
	type output struct {
		priv  glome.PrivateKey
		found bool
	}

	for name, k := range []struct {
		in   input
		want output
	}{
		{
			in:   input{priv: glome.PrivateKey([32]byte{}), index: 0},
			want: output{priv: glome.PrivateKey([32]byte{}), found: true},
		}, {
			in: input{
				priv: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
					192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
					67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
				index: 111,
			},
			want: output{
				priv: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
					192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
					67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
				found: true,
			},
		},
	} {
		manager := NewKeyManager()
		if _, found := manager.Read(k.in.index); found {
			t.Errorf("test %v failed; found key on index %v", name, k.in.index)
		}
		if err := manager.Add(k.in.priv, k.in.index); err != nil {
			t.Fatalf("test %v, unexpected error: %v ", name, err.Error())
		}
		if key, found := manager.Read(k.in.index); key != k.want.priv || found != k.want.found {
			t.Errorf("test %v failed on input %#v; want %v, got %v,%v", name, k.in, k.want, key, found)
		}
	}
}

func TestDropAllReplace(t *testing.T) {
	preloadManager := NewKeyManager()
	preloadManager.Add(glome.PrivateKey([32]byte{}), 0)

	type input struct {
		keys    []PrivateKey
		manager *KeyManager
	}

	for name, k := range []struct {
		in   input
		want map[uint8]glome.PrivateKey
	}{
		{
			in: input{
				keys: []PrivateKey{
					PrivateKey{Value: glome.PrivateKey([32]byte{}), Index: 0},
					PrivateKey{
						Value: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
							192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
							67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
						Index: 1,
					},
				},
				manager: NewKeyManager(),
			},
			want: map[uint8]glome.PrivateKey{
				0: glome.PrivateKey([32]byte{}),
				1: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
					192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
					67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
			},
		}, {
			in: input{
				keys: []PrivateKey{
					PrivateKey{Value: glome.PrivateKey([32]byte{}), Index: 0},
					PrivateKey{
						Value: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
							192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
							67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
						Index: 1,
					},
				},
				manager: preloadManager,
			},

			want: map[uint8]glome.PrivateKey{
				0: glome.PrivateKey([32]byte{}),
				1: glome.PrivateKey([32]byte{49, 244, 125, 133, 0, 40, 7,
					192, 7, 90, 5, 208, 234, 104, 66, 68, 251, 237, 187, 132,
					67, 236, 108, 164, 162, 199, 41, 89, 128, 95, 26, 190}),
			},
		},
	} {
		k.in.manager.DropAllReplace(k.in.keys)
		if !reflect.DeepEqual(k.in.manager.indexToPriv, k.want) {
			t.Errorf("test %v failed; got %#v, want %#v", name, k.in.manager.indexToPriv, k.want)
		}
	}
}
