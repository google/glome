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

package glome

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func handle(e error, t *testing.T) {
	if e != nil {
		t.Fatalf("Unexpected Error: " + e.Error())
	}
}

// Stores test vectors from protocol reference. Each variable is named after
// a row of the test table. For the purpose of testing, we consider that user A
// is always the one that sends the message (therefore, we change the role of A
// and B in Vector #2)
type testVector struct {
	kap     []byte //kap = K_a'(k sub a *p*rime)
	ka      []byte
	kbp     []byte
	kb      []byte
	counter uint8
	msg     []byte
	ks      []byte
	tag     []byte
}

func (tv *testVector) Dialogs(t *testing.T) (*Dialog, *Dialog) {
	aPriv, err := PrivateKeyFromSlice(tv.kap)
	if err != nil {
		t.Fatalf("Unexpected Error: " + err.Error())
	}
	aPub, err := PublicKeyFromSlice(tv.ka)
	if err != nil {
		t.Fatalf("Unexpected Error: " + err.Error())
	}
	bPriv, err := PrivateKeyFromSlice(tv.kbp)
	if err != nil {
		t.Fatalf("Unexpected Error: " + err.Error())
	}
	bPub, err := PublicKeyFromSlice(tv.kb)
	if err != nil {
		t.Fatalf("Unexpected Error: " + err.Error())
	}
	sending, err := aPriv.Exchange(bPub)
	if err != nil {
		t.Fatalf("Unexpected Error: " + err.Error())
	}
	receiving, err := bPriv.Exchange(aPub)
	if err != nil {
		t.Fatalf("Unexpected Error: " + err.Error())
	}

	return sending, receiving
}

func decodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("Invalid hexadecimal string %v input in test", s))
	}
	return b
}

// Stores Tests Samples. Left out for better accessibility
func tests() map[string]testVector {
	return map[string]testVector{
		"Test Vector 1": {
			kap:     decodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
			ka:      decodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
			kbp:     decodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
			kb:      decodeString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
			counter: 0,
			msg:     []byte("The quick brown fox"),
			ks:      decodeString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
			tag:     decodeString("9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3"),
		},
		"Test Vector 2": {
			kap:     decodeString("b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d"),
			ka:      decodeString("d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647"),
			kbp:     decodeString("fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead"),
			kb:      decodeString("872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376"),
			counter: 100,
			msg:     []byte("The quick brown fox"),
			ks:      decodeString("4b1ee05fcd2ae53ebe4c9ec94915cb057109389a2aa415f26986bddebf379d67"),
			tag:     decodeString("06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277"),
		},
	}
}

func TestKeyGeneration(t *testing.T) {
	for name, tv := range tests() {
		send, rec := tv.Dialogs(t)
		name := name

		t.Run(name, func(t *testing.T) {
			for _, k := range []struct {
				input []byte
				want  []byte
			}{
				{input: send.sendingKey(), want: append(tv.ks, append(tv.kb, tv.ka...)...)},
				{input: send.receivingKey(), want: append(tv.ks, append(tv.ka, tv.kb...)...)},
				{input: rec.sendingKey(), want: append(tv.ks, append(tv.ka, tv.kb...)...)},
				{input: rec.receivingKey(), want: append(tv.ks, append(tv.kb, tv.ka...)...)},
			} {
				if !bytes.Equal(k.input, k.want) {
					t.Errorf("%v failed; got: %v, want %v", name, k.want, k.input)
				}
			}
		})
	}
}

func TestTagGeneration(t *testing.T) {
	for name, tv := range tests() {
		send, _ := tv.Dialogs(t)
		if got := send.Tag(tv.msg, tv.counter); !bytes.Equal(tv.tag, got) {
			t.Errorf("%v failed; got: %v, want %v", name, got, tv.tag)
		}
	}
}

func TestCheckFailIfIncorrectTag(t *testing.T) {
	for name, tv := range tests() {
		_, rec := tv.Dialogs(t)
		name := name

		type input struct {
			t   []byte
			msg []byte
			c   uint8
		}

		t.Run(name, func(t *testing.T) {
			for _, k := range []struct {
				in   input
				want bool
			}{
				{in: input{t: tv.tag, msg: tv.msg, c: tv.counter}, want: true},
				{in: input{t: []byte{23, 45, 67, 87, 65, 43, 22}, msg: tv.msg, c: tv.counter}, want: false},
				{in: input{t: tv.tag, msg: []byte("this is not the message"), c: tv.counter}, want: false},
				{in: input{t: tv.tag, msg: tv.msg, c: 23}, want: false},
			} {
				got := rec.Check(k.in.t, k.in.msg, k.in.c)
				if !k.want == got {
					t.Fatalf("%v failed; got: %v, want: %v", name, got, k.want)
				}
			}
		})
	}
}
