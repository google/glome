package v2

import (
	"reflect"
	"testing"
)

type messageTestCase struct {
	msg     *Message
	encoded string
}

var messageTestCases = []messageTestCase{
	{
		encoded: "myhost/root",
		msg:     &Message{HostID: "myhost", Action: "root"},
	},
	{
		encoded: "mytype:myhost/root",
		msg:     &Message{HostIDType: "mytype", HostID: "myhost", Action: "root"},
	},
	{
		encoded: "escaping/special%20action%CC",
		msg:     &Message{HostID: "escaping", Action: "special action\xcc"},
	},
	{
		encoded: "pairs/user=root;exec=%2Fbin%2Fmksh",
		msg:     &Message{HostID: "pairs", Action: "user=root;exec=/bin/mksh"},
	},
}

func TestEncodeMessage(t *testing.T) {
	for _, tc := range messageTestCases {
		t.Run(tc.encoded, func(t *testing.T) {
			got := tc.msg.Encode()
			if got != tc.encoded {
				t.Errorf("%#v.Encode() == %q, want %q", tc.msg, got, tc.encoded)
			}
		})
	}
}

func TestDecodeMessage(t *testing.T) {
	for _, tc := range messageTestCases {
		t.Run(tc.encoded, func(t *testing.T) {
			got, err := decodeMessage(tc.encoded)
			if err != nil {
				t.Fatalf("decodeMessage(%q) failed: %v", tc.encoded, err)
			}
			if !reflect.DeepEqual(got, tc.msg) {
				t.Errorf("decodeMessage(%q) == %#v, want %#v", tc.encoded, got, tc.msg)
			}
		})
	}
}
