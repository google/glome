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
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/glome/go/glome"
)

const (
	// Minimal acceptable length of a handshake. 1 byte for the prefix, 32 bytes for the key
	minHandshakeLen = 1 + glome.PublicKeySize
)

var (
	// ErrInvalidURLFormat denotes that the URL has a wrong format.
	ErrInvalidURLFormat = fmt.Errorf("URL is malformed")
	// ErrInvalidHandshakeLen denotes that the handshake is too short.
	ErrInvalidHandshakeLen = fmt.Errorf("handshake length is small: should be at least %d", minHandshakeLen)
	// ErrVersionNotSupported denotes that the version of glome-login URL format is not supported.
	ErrVersionNotSupported = fmt.Errorf("version not supported")
	// ErrInvalidPrefixType denotes that the prefix type is invalid.
	ErrInvalidPrefixType = fmt.Errorf("invalid prefix type")
	// ErrIncorrectTag denotes that received tag is incorrect.
	ErrIncorrectTag = fmt.Errorf("invalid tag")
	// ErrResponseNotInitialized denotes that the response is not initialized.
	ErrResponseNotInitialized = fmt.Errorf("response is not initialized")
	// ErrServerKeyNotFound server key not found.
	ErrServerKeyNotFound = fmt.Errorf("server key not found")
)

var (
	validURLPrefix = regexp.MustCompile(`/(?P<v>v[1-9][0-9]*)/(?P<handshake>[\w=-]+)/`)
)

// Message struct represents the context required for authorization.
// It contains HostIDType - type of identity, HostID - identity of the target (e.g. hostname, serial number, etc.),
// Action - action that is being authorized.
type Message struct {
	HostIDType string
	HostID     string
	Action     string
}

// Construct returns a message from a Message according to the format: [<hostid-type>:]<hostid>[/<action>].
// URL escaping is optional.
func (m *Message) Construct(esc bool) []byte {
	hostIDType := ""
	hostID := ""
	action := ""
	if esc {
		hostIDType = escape(m.HostIDType)
		hostID = escape(m.HostID)
	} else {
		hostIDType = m.HostIDType
		hostID = m.HostID
	}

	if hostIDType != "" {
		hostIDType += ":"
	}

	if m.Action != "" {
		action = "/" + m.Action
	}
	return []byte(hostIDType + hostID + action)
}

// Escapes the string so it can be safely placed inside a URL path segment,
// replacing "/#?" special characters and not replacing "!*'();:@&=+$,[]" special characters.
func escape(s string) string {
	res := url.PathEscape(s)
	for _, c := range "!*'();:@&=+$,[]" {
		st := string(c)
		strings.Replace(res, url.PathEscape(st), st, -1)
	}
	return res
}

// Handshake struct represents the context required for constructing the handshake.
// It contains Prefix - either service key or its id, UserKey - user's public ephemeral key,
// MessageTagPrefix - tag calculated under Message.
type Handshake struct {
	Prefix           byte
	UserKey          glome.PublicKey
	MessageTagPrefix []byte
}

// URLResponse struct represents the context required for the URL constructing.
// It contains V - URL format version (currently always 1), HandshakeInfo - handshake info,
// Msg - message info, d - glome.Dialog for the tag managing.
type URLResponse struct {
	V             byte
	HandshakeInfo Handshake
	Msg           Message
	d             *glome.Dialog
}

// NewResponse returns a new URLResponse corresponding to the given arguments.
func NewResponse(serviceKeyID uint8, serviceKey glome.PublicKey, userKey glome.PrivateKey,
	V byte, hostIDType string, hostID string, action string, tagLen uint) (*URLResponse, error) {
	var prefix byte
	var r URLResponse

	r.V = V

	d, err := userKey.TruncatedExchange(&serviceKey, 1)
	if err != nil {
		return nil, err
	}
	r.d = d

	r.Msg = Message{hostIDType, hostID, action}

	if serviceKeyID == 0 {
		// If no key ID was specified, send the first key byte as the ID.
		prefix = serviceKey[0] & 0x7f
	} else {
		prefix = serviceKeyID & 0x7f
	}
	userPublic, err := userKey.Public()
	if err != nil {
		return nil, err
	}
	HandshakeInfo := Handshake{prefix, *userPublic, r.Tag(tagLen)}
	r.HandshakeInfo = HandshakeInfo

	return &r, nil
}

// ValidateAuthCode checks if the received tag corresponding to the base64-url encoded message constructed from the Message.
// Returns true if the received tag is empty.
func (r *URLResponse) ValidateAuthCode(tag []byte) bool {
	if len(tag) == 0 {
		return true
	}
	return r.d.Check(tag, r.Msg.Construct(false), 0)
}

// Tag returns the tag corresponding to the Msg. The returned tag is calculated with usage of sendingKey.
func (r *URLResponse) Tag(len uint) []byte {
	return r.d.Tag(r.Msg.Construct(false), 0)[:len]
}

// EncToken returns a base64-encoded response token.
func (r *URLResponse) EncToken() string {
	return base64.URLEncoding.EncodeToString(r.Tag(glome.MaxTagSize)) // TODO: passing the tag len as param?
}

// Client side glome-login handler. Should be constructed under NewClient constructor.
type Client struct {
	ServiceKey   glome.PublicKey
	UserKey      glome.PrivateKey
	ServiceKeyID uint8
	TagLen       uint
	response     *URLResponse
}

// NewClient is a Client constructor. Sets Client.ServiceKey, Client.UserKey, Client.ServiceKeyID, Client.TagLen
// to the corresponding values and Client.response to nil.
func NewClient(sk glome.PublicKey, uk glome.PrivateKey, sID uint8, tagLen uint) *Client {
	return &Client{sk, uk, sID, tagLen, nil}
}

// Construct returns a request to the server according to the format: /v<V>/<glome-handshake>[/<message>]/.
func (c *Client) Construct(V byte, hostIDType string, hostID string, action string) (string, error) {
	r, err := NewResponse(c.ServiceKeyID, c.ServiceKey, c.UserKey, V, hostIDType, hostID, action, c.TagLen)
	if err != nil {
		return "", err
	}
	c.response = r

	var handshake = c.constructHandshake()
	var msg = c.response.Msg.Construct(true)
	var u = fmt.Sprintf("/v%d/%s/", c.response.V, handshake)
	if len(msg) > 0 {
		u += fmt.Sprintf("%s/", msg)
	}
	return u, nil
}

// constructHandshake returns base64-url encoded handshake. The handshake is constructed following the format:
//		glome-handshake := base64url(
//    		<prefix-type>
//    		<prefix7>
//    		<eph-key>
//    		[<prefixN>]
//  	).
func (c *Client) constructHandshake() string {
	var handshake []byte
	h := c.response.HandshakeInfo

	handshake = append(handshake, h.Prefix)
	handshake = append(handshake, h.UserKey[:]...)
	handshake = append(handshake, h.MessageTagPrefix[:]...)
	return base64.URLEncoding.EncodeToString(handshake[:])
}

// ValidateAuthCode checks if the received tag corresponding to the base64-url encoded message constructed from the Message.
func (c *Client) ValidateAuthCode(tag string) (bool, error) {
	dTag, err := base64.URLEncoding.DecodeString(completeBase64S(tag))
	if err != nil {
		return false, err
	}

	if c.response == nil {
		return false, ErrResponseNotInitialized
	}
	return c.response.ValidateAuthCode(dTag), nil
}

// completeBase64S completes the base64 string with padding if it was truncated and couldn't be correctly decoded.
func completeBase64S(s string) string {
	n := len(s)
	switch n % 4 {
	case 0:
		return s
	case 1:
		return s[:n-1]
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		panic("math fail")
	}
}

func (c *Client) Response() *URLResponse {
	return c.response
}

// Server side glome-login lib handler. Receives the server's private key fetcher function,
// which returns an error if the key couldn't be calculated.
type Server struct {
	KeyFetcher func(uint8) (glome.PrivateKey, error)
}

// ParseURLResponse parses the url, checks whether it is formed correctly and validates the client's tag, received from the URL.
func (s *Server) ParseURLResponse(url string) (*URLResponse, error) {
	response := URLResponse{}

	names := validURLPrefix.SubexpNames()[1:]        // as "The name for the first sub-expression is names[1].."
	parsed := validURLPrefix.FindStringSubmatch(url) // save first element (full substring) to be trimmed later in url
	if parsed == nil {
		return nil, ErrInvalidURLFormat
	}
	reqParts := map[string]string{}
	for i := 0; i < len(names); i++ {
		reqParts[names[i]] = parsed[i+1]
	}

	v, err := parseVersion(reqParts["v"])
	if err != nil {
		return nil, err
	}
	response.V = v

	handshake, err := parseHandshake(reqParts["handshake"])
	if err != nil {
		return nil, err
	}
	response.HandshakeInfo = *handshake

	sPrivKey, err := s.KeyFetcher(handshake.Prefix)
	if err != nil {
		return nil, ErrServerKeyNotFound
	}
	response.d, err = sPrivKey.TruncatedExchange(&handshake.UserKey, 1)
	if err != nil {
		return nil, err
	}

	url = strings.TrimPrefix(url, parsed[0])
	if url == "" { // <message> is empty
		if response.ValidateAuthCode(response.HandshakeInfo.MessageTagPrefix) != true {
			return nil, ErrIncorrectTag
		}
		return &response, nil
	}
	if url[len(url)-1] == '/' { // check last slash
		url = strings.TrimSuffix(url, "/")
		hostAndAction := strings.SplitN(url, "/", 2)

		msg, err := parseMsg(hostAndAction)
		if err != nil {
			return nil, err
		}
		response.Msg = *msg

		if response.ValidateAuthCode(response.HandshakeInfo.MessageTagPrefix) != true {
			return nil, ErrIncorrectTag
		}
		return &response, nil
	}
	return nil, ErrInvalidURLFormat
}

// parseVersion returns the parsed version of the URL format version. Returns ErrVersionNotSupported error,
// if the parsed version is not supported.
func parseVersion(v string) (byte, error) {
	num, err := strconv.Atoi(v[1:])
	if err != nil {
		return 0, err
	}
	if num != 1 { // current version
		return 0, ErrVersionNotSupported
	}

	return byte(num), nil
}

// parseHandshake returns the parsed version of the URL handshake.
// The handshake should satisfy the following format:
//		glome-handshake := base64url(
//    		<prefix-type>
//    		<prefix7>
//    		<eph-key>
//    		[<prefixN>]
//  	).
func parseHandshake(handshake string) (*Handshake, error) {
	dHandshake, err := base64.URLEncoding.DecodeString(handshake)
	if err != nil {
		return nil, err
	}
	if len(dHandshake) < minHandshakeLen {
		return nil, ErrInvalidHandshakeLen
	}

	prefix := dHandshake[0]
	if prefix>>7 != 0 { // check prefix-type
		return nil, ErrInvalidPrefixType
	}

	userKey, err := glome.PublicKeyFromSlice(dHandshake[1:minHandshakeLen])
	if err != nil {
		return nil, err
	}

	msgTagPrefix := dHandshake[minHandshakeLen:]
	if len(msgTagPrefix) > glome.MaxTagSize {
		return nil, glome.ErrInvalidTagSize
	}

	return &Handshake{prefix, *userKey, msgTagPrefix}, nil
}

// parseMsg returns the parsed version of the URL message.
// The message should satisfy the following format: [<hostid-type>:]<hostid>[/<action>].
func parseMsg(m []string) (*Message, error) {
	var hostIDType, hostID, action string
	u, err := url.QueryUnescape(m[0])
	if err != nil {
		return nil, err
	}

	var host = strings.SplitN(u, ":", 2)
	if len(host) == 2 { // <hostid-type> is present
		hostIDType = host[0]
		hostID = host[1]
	} else {
		hostID = host[0]
	}

	if len(m) == 2 { // <action> is not empty
		action = m[1]
	}

	return &Message{hostIDType, hostID, action}, nil
}
