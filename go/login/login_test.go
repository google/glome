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

package login

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/google/glome/go/glome"
)

var serviceKeyIDs = []uint8{1, 0}

type testVector struct {
	kap        []byte
	ka         []byte
	kbp        []byte
	kb         []byte
	ks         []byte
	prefix     byte
	hostIDType string
	hostID     string
	action     string
	msg        []byte
	url        string
	prefixN    []byte
	tag        []byte
	token      string
}

func fatal(reason string, t *testing.T, testName string, tv int) {
	t.Fatalf("%s failed for test vector %d. %s", testName, tv, reason)
}

type keyPair struct {
	priv glome.PrivateKey
	pub  glome.PublicKey
}

func decodeString(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Invalid hexadecimal string %v.", s)
	}
	return b
}

func keys(t *testing.T, kp []byte, k []byte) *keyPair {
	aPriv, err := glome.PrivateKeyFromSlice(kp)
	if err != nil {
		t.Fatalf("PrivateKeyFromSlice failed: %v", err)
	}

	aPub, err := glome.PublicKeyFromSlice(k)
	if err != nil {
		t.Fatalf("PublicKeyFromSlice failed: %v", err)
	}

	return &keyPair{*aPriv, *aPub}
}

func (tv *testVector) dialog(t *testing.T) (*glome.Dialog, *glome.Dialog) {
	clientKP := keys(t, tv.kap, tv.ka)
	serverKP := keys(t, tv.kbp, tv.kb)

	sending, err := clientKP.priv.Exchange(&serverKP.pub)
	if err != nil {
		t.Fatalf("Client key exchange failed: %v", err)
	}
	receiving, err := serverKP.priv.Exchange(&clientKP.pub)
	if err != nil {
		t.Fatalf("Server key exchange failed: %v", err)
	}

	return sending, receiving
}

func testVectors(t *testing.T) []testVector {
	return []testVector{
		{
			kap:        decodeString(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
			ka:         decodeString(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
			kbp:        decodeString(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
			kb:         decodeString(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
			ks:         decodeString(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
			prefix:     byte(1),
			hostIDType: "",
			hostID:     "my-server.local",
			action:     "shell/root",
			msg:        []byte("my-server.local/shell/root"),
			url:        "/v1/AYUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q0PU=/my-server.local/shell/root/",
			prefixN:    decodeString(t, "d0f59d0b17cb155a1b9cd2b5cdea3a17f37a200e95e3651af2c88e1c5fc8108e"),
			tag:        decodeString(t, "9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3"),
			token:      "lyHuaHuCck",
		},

		{
			kap:        decodeString(t, "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead"),
			ka:         decodeString(t, "872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376"),
			kbp:        decodeString(t, "b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d"),
			kb:         decodeString(t, "d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647"),
			ks:         decodeString(t, "4b1ee05fcd2ae53ebe4c9ec94915cb057109389a2aa415f26986bddebf379d67"),
			prefix:     byte(0x51),
			hostIDType: "serial-number",
			hostID:     "1234567890=ABCDFGH/#?",
			action:     "reboot",
			msg:        []byte("serial-number:1234567890=ABCDFGH/#?/reboot"),
			url:        "/v1/UYcvQ1u4uJ0OOtYqouURB07hleHDnvaogAFBi-ZW48N2/serial-number:1234567890=ABCDFGH%2F%23%3F/reboot/",
			prefixN:    decodeString(t, "dff5aae753a8bdce06038a20adcdb26c7be19cb6bd05a7850fae542f4af29720"),
			tag:        decodeString(t, "06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277"),
			token:      "p8M_BUKj7zXBVM2JlQhNYFxs4J-DzxRAps83ZaNDquY=",
		},
	}
}

func clientsAndServers(t *testing.T, tvs []testVector) ([]Client, []Server) {
	clientTagsLen := []uint{2, 0}
	keyPairs := make([][]keyPair, len(tvs))
	for i, tv := range tvs {
		keyPairs[i] = append(keyPairs[i], *keys(t, tv.kap, tv.ka), *keys(t, tv.kbp, tv.kb))
	}

	var clients []Client
	var servers []Server
	for tv := 0; tv < len(tvs); tv++ {
		clients = append(clients, *NewClient(keyPairs[tv][1].pub, keyPairs[tv][0].priv, serviceKeyIDs[tv], clientTagsLen[tv]))
		sPrivKey := keyPairs[tv][1].priv
		servers = append(servers,
			Server{func(u uint8) (glome.PrivateKey, error) {
				return sPrivKey, nil
			}})
	}
	return clients, servers
}

func parsedResponses(t *testing.T, tvs []testVector) []URLResponse {
	_, servers := clientsAndServers(t, testVectors(t))
	var parsedResponses []URLResponse

	for i, tv := range tvs {
		t.Run("Test vector "+fmt.Sprint(i+1), func(t *testing.T) {
			resp, err := servers[i].ParseURLResponse(tv.url)
			if err != nil {
				fatal(fmt.Sprintf("Expected: parsed URL, got error: %#v.", err.Error()), t, "parsedResponses", i+1)
			}
			parsedResponses = append(parsedResponses, *resp)
		})
	}

	return parsedResponses
}

func TestURLParsedCorrectly(t *testing.T) {
	tvs := testVectors(t)
	responses := parsedResponses(t, tvs)
	for i, tv := range tvs {
		t.Run("Test vector "+fmt.Sprint(i+1), func(t *testing.T) {
			// Check message parsed correctly
			msg := responses[i].Msg
			for _, m := range []struct {
				expected string
				got      string
			}{
				{expected: tv.hostIDType, got: msg.HostIDType},
				{expected: tv.hostID, got: msg.HostID},
				{expected: tv.action, got: msg.Action},
			} {
				if m.expected != m.got {
					fatal(fmt.Sprintf("Expected: %#v, got: %#v.", m.expected, m.got), t, "TestURLParsedCorrectly", i+1)
				}
			}

			// Check handshake parsed correctly
			h := responses[i].HandshakeInfo
			if responses[i].ValidateAuthCode(h.MessageTagPrefix) != true {
				fatal("The tags are different.", t, "TestURLParsedCorrectly", i+1)
			}
		})
	}
}

func TestServerToken(t *testing.T) {
	tvs := testVectors(t)
	responses := parsedResponses(t, tvs)
	for i, tv := range tvs {
		t.Run("Test vector "+fmt.Sprint(i+1), func(t *testing.T) {
			if !(strings.HasPrefix(responses[i].EncToken(), tv.token)) {
				fatal(fmt.Sprintf("The tags are different: expected %#v, got %#v.", tv.token, responses[i].EncToken()),
					t, "TestServerToken", i+1)
			}
		})
	}
}

func TestURLResponseConstruction(t *testing.T) {
	tvs := testVectors(t)
	clients, _ := clientsAndServers(t, tvs)
	for i, tv := range tvs {
		t.Run("Test vector "+fmt.Sprint(i+1), func(t *testing.T) {
			resp, err := clients[i].Construct(1, tv.hostIDType, tv.hostID, tv.action)
			if err != nil {
				fatal(fmt.Sprintf("Error while constructing URL: %s.", err.Error()), t, "TestURLResponseConstruction", i+1)
			}

			if resp != tv.url {
				fatal(fmt.Sprintf("The URLs are different: expected %#v, got %#v.", tv.url, resp), t, "TestURLResponseConstruction", i+1)
			}

			eq, err := clients[i].ValidateAuthCode(tv.token)
			if err != nil {
				fatal(fmt.Sprintf("Error while validating authorization code: %s.", err.Error()), t, "TestURLResponseConstruction", i+1)
			}

			if !eq {
				fatal("The tokens are different.", t, "TestURLResponseConstruction", i+1)
			}
		})
	}
}
