package v2_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/glome/go/glome"
	v2 "github.com/google/glome/go/login/v2"
)

func unhexPrivateKey(s string) *glome.PrivateKey {
	var buf [32]byte
	n, err := hex.Decode(buf[:], []byte(s))
	if err != nil {
		panic(err)
	}
	if n != 32 {
		panic("hex literal had unexpected length")
	}
	key := glome.PrivateKey(buf)
	return &key
}

func Example() {
	// Error handling omitted for clarity.

	// This example demonstrates the basic flow of a GLOME Login. Our cast has 3 protagonists:
	// * The _client_ is a short-lived process guarding access to a computer somewhere.
	// * The _server_ is a long-lived centralized process authorizing access to computers.
	// * The _operator_ tries to access the computer and interacts with both _client_ and _server_.

	// ===== Server Side =====

	// This is the permanent setup of the authorization server. For this example, it uses only one
	// key, with index 0.
	serverKey := unhexPrivateKey("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	server, _ := v2.NewResponder(map[uint8]*glome.PrivateKey{0: serverKey})

	// ===== Client Side =====

	// The client needs to be configured with at least a public key of the server. For this
	// example, we rely on key auto-discovery. To be safe against key mismatches on the server
	// side, we include a small tag prefix for error detection.
	serverPublickey, _ := serverKey.Public()
	client := &v2.Challenger{
		PublicKey:              serverPublickey,
		MessageTagPrefixLength: 3,
	}

	// The client crafts a message for the server, asking it to authorize a specific action. In
	// this example, the client identifies itself as myhost and the operator is attempting to log
	// in as root.
	msg := &v2.Message{
		HostID: "myhost",
		Action: "user=root",
	}
	// The client creates a challenge and hands the encoded version of the challenge to the
	// operator, who then takes the challenge to the server, somehow.
	clientChallenge, _ := client.Challenge(msg)
	encodedChallenge := clientChallenge.Encode()

	// ===== Server Side =====

	serverChallenge, err := server.Accept(encodedChallenge)
	if err != nil {
		panic(err)
	}
	// The server verifies that the operator is authorized for the message ...
	fmt.Printf("Message: %s\n", serverChallenge.Message.Encode())
	// ... and hands the operator an encoded response.
	response := serverChallenge.Response

	// The operator transfers the response back to the client, somehow.

	// ===== Client Side =====

	// The client checks the response provided by the operator and grants access to the computer.
	if clientChallenge.Verify(response) {
		fmt.Println("authorized")
	} else {
		fmt.Println("forbidden")
	}

	// Output:
	// Message: myhost/user=root
	// authorized
}

func Example_withIndex() {
	// This is like Example(), but using a server key index.

	// ===== Server Side =====

	serverKey := unhexPrivateKey("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	serverKeyIndex := uint8(42)
	server, _ := v2.NewResponder(map[uint8]*glome.PrivateKey{serverKeyIndex: serverKey})

	// ===== Client Side =====

	serverPublickey, _ := serverKey.Public()
	client := &v2.Challenger{
		PublicKey: serverPublickey,
		KeyIndex:  &serverKeyIndex,
	}

	msg := &v2.Message{
		HostID: "myhost",
		Action: "user=root",
	}
	clientChallenge, _ := client.Challenge(msg)
	encodedChallenge := clientChallenge.Encode()

	// ===== Server Side =====

	serverChallenge, err := server.Accept(encodedChallenge)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Message: %s\n", serverChallenge.Message.Encode())
	response := serverChallenge.Response

	// ===== Client Side =====

	if clientChallenge.Verify(response) {
		fmt.Println("authorized")
	} else {
		fmt.Println("forbidden")
	}

	// Output:
	// Message: myhost/user=root
	// authorized
}

func ptr(i uint8) *uint8 {
	return &i
}

type testVector struct {
	index                  int
	alice                  string
	bob                    string
	keyIndex               *uint8
	messageTagPrefixLength uint8
	minResponseLength      *uint8
	msg                    *v2.Message

	challenge string
	response  string
}

var testVectors = []testVector{
	{
		index:                  1,
		alice:                  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
		bob:                    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
		keyIndex:               ptr(0),
		messageTagPrefixLength: 3,
		minResponseLength:      ptr(12),
		msg: &v2.Message{
			HostIDType: "mytype",
			HostID:     "myhost",
			Action:     "root",
		},
		challenge: "v2/gIUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05qlyPH/mytype:myhost/root/",
		response:  "BB4BYjXonlIRtXZORkQ5bF5xTZwW6o60ylqfCuyAHTQ=",
	},
	{
		index: 2,
		alice: "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead",
		bob:   "b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d",
		msg: &v2.Message{
			HostID: "myhost",
			Action: "exec=/bin/sh",
		},
		challenge: "v2/R4cvQ1u4uJ0OOtYqouURB07hleHDnvaogAFBi-ZW48N2/myhost/exec=%2Fbin%2Fsh/",
		response:  "ZmxczN4x3g4goXu-A2AuuEEVftgS6xM-6gYj-dRrlis=",
	},
}

func TestSpec(t *testing.T) {
	for _, tc := range testVectors {
		t.Run(fmt.Sprintf("vector-%d", tc.index), func(t *testing.T) {
			alice := unhexPrivateKey(tc.alice)
			bob := unhexPrivateKey(tc.bob)
			bobPub, err := bob.Public()
			if err != nil {
				t.Fatalf("private key from test vector broken: %v", err)
			}

			c := &v2.Challenger{
				PublicKey:              bobPub,
				KeyIndex:               tc.keyIndex,
				MessageTagPrefixLength: tc.messageTagPrefixLength,
				RNG:                    bytes.NewBuffer(alice[:]),
			}
			if tc.minResponseLength != nil {
				c.MinResponseLength = *tc.minResponseLength
			}
			cc, err := c.Challenge(tc.msg)
			if err != nil {
				t.Fatalf("Challenge generation failed: %v", err)
			}
			gotChallenge := cc.Encode()
			if gotChallenge != tc.challenge {
				t.Errorf("Unexpected encoding:\ngot:\t%s\nwant:\t%s", gotChallenge, tc.challenge)
			}

			r, err := v2.NewResponder(map[uint8]*glome.PrivateKey{0: bob})
			if err != nil {
				t.Fatalf("NewResponder() failed: %v", err)
			}
			sc, err := r.Accept(tc.challenge)
			if err != nil {
				t.Fatalf("Accept(%q) failed: %v", gotChallenge, err)
			}
			if !reflect.DeepEqual(tc.msg, sc.Message) {
				t.Errorf("Responder parsed wrong message: got %#v, want %#v", sc.Message, tc.msg)
			}

			if sc.Response != tc.response {
				t.Errorf("Responder generated wrong response: got %q, want %q", sc.Response, tc.response)
			}

			min := uint8(10)
			if tc.minResponseLength != nil {
				min = *tc.minResponseLength
			}

			for i := 1; i < int(min); i++ {
				if cc.Verify(tc.response[:i]) {
					t.Errorf("Verification succeeded with response length %d, although the minimum is %d", i, min)
				}
			}
			for i := int(min); i <= len(tc.response); i++ {
				if !cc.Verify(tc.response[:i]) {
					t.Errorf("Verification failed with %d characters, although the minimum is %d", i, min)
				}
			}
		})
	}
}
