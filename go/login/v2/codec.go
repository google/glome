package v2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"

	"github.com/google/glome/go/glome"
)

// Message represents the context required for authorization.
type Message struct {
	HostIDType string // type of identity
	HostID     string // identity of the target (e.g. hostname, serial number, etc.)
	Action     string // action that is being authorized
}

// escape a URI path minimally according to RFD001.
func escape(s string) string {
	res := url.PathEscape(s)
	for _, c := range "!*'();:@&=+$,[]" {
		st := string(c)
		res = strings.Replace(res, url.PathEscape(st), st, -1)
	}
	return res
}

// Encode the message into its URI path representation.
func (m *Message) Encode() string {
	sb := &strings.Builder{}
	if len(m.HostIDType) > 0 {
		sb.WriteString(escape(m.HostIDType))
		sb.WriteByte(':')
	}
	sb.WriteString(escape(m.HostID))
	sb.WriteByte('/')
	sb.WriteString(escape(m.Action))
	return sb.String()
}

func decodeMessage(s string) (*Message, error) {
	m := &Message{}

	subs := strings.Split(s, "/")
	if len(subs) != 2 {
		return nil, errors.New("message format error")
	}

	hostSegment, err := url.PathUnescape(subs[0])
	if err != nil {
		return nil, err
	}
	hostParts := strings.SplitN(hostSegment, ":", 2)
	if len(hostParts) > 1 {
		m.HostIDType = hostParts[0]
		m.HostID = hostParts[1]
	} else {
		m.HostID = hostParts[0]
	}

	action, err := url.PathUnescape(subs[1])
	if err != nil {
		return nil, err
	}
	m.Action = action

	return m, nil
}

type handshake struct {
	Index  uint8
	Prefix *byte

	PublicKey        *glome.PublicKey
	MessageTagPrefix []byte
}

func (h *handshake) Encode() string {
	data := bytes.NewBuffer(nil)
	if h.Prefix != nil {
		data.WriteByte(*h.Prefix)
	} else {
		data.WriteByte(1<<7 | h.Index)
	}
	data.Write(h.PublicKey[:])
	data.Write(h.MessageTagPrefix)

	return base64.URLEncoding.EncodeToString(data.Bytes())
}

func decodeHandshake(s string) (*handshake, error) {
	data, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(data) < 33 {
		return nil, errors.New("handshake too short")
	}

	h := &handshake{}

	if data[0]>>7 == 0 { // check Prefix-type
		h.Prefix = &data[0]
	} else {
		h.Index = data[0] % (1 << 7)
	}

	key, err := glome.PublicKeyFromSlice(data[1 : glome.PublicKeySize+1])
	if err != nil {
		return nil, err
	}
	h.PublicKey = key

	msgTagPrefix := data[glome.PublicKeySize+1:]
	if len(msgTagPrefix) > glome.MaxTagSize {
		return nil, errors.New("message tag prefix too long")
	}
	if len(msgTagPrefix) > 0 {
		h.MessageTagPrefix = msgTagPrefix
	}

	return h, nil
}
