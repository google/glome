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
	// Minimal acceptable length of a handshake. 1 byte for the Prefix, 32 bytes for the key.
	minHandshakeLen = 1 + glome.PublicKeySize
)

var (
	validURLPrefix = regexp.MustCompile(`/(?P<v>v[1-9][0-9]*)/(?P<handshake>[\w=-]+)/`)
)

var (
	// ErrInvalidHandshakeLen denotes that the handshake is too short.
	ErrInvalidHandshakeLen = fmt.Errorf("handshake length is too small: should be at least %d", minHandshakeLen)
	// ErrInvalidPrefixType denotes that the prefix-type is invalid.
	ErrInvalidPrefixType = fmt.Errorf("invalid prefix type: should be a 0")
	// ErrIncorrectTag denotes that received tag is incorrect.
	ErrIncorrectTag = fmt.Errorf("invalid tag")
	// ErrResponseNotInitialized denotes that the response is not initialized.
	ErrResponseNotInitialized = fmt.Errorf("response is not initialized")
)

// ErrInvalidURLFormat denotes that the URL has a wrong format.
type ErrInvalidURLFormat struct {
	URL string
}

// ErrServerKeyNotFound denotes that there is no private server key associated with a Prefix.
type ErrServerKeyNotFound struct {
	Prefix byte
}

// ErrVersionNotSupported denotes that the V of glome-login URL format is not supported.
type ErrVersionNotSupported struct {
	V int
}

func (err *ErrInvalidURLFormat) Error() string {
	return fmt.Sprintf("URL %v doesn't satisfy the format %s.", err.URL, validURLPrefix.String())
}

func (err *ErrServerKeyNotFound) Error() string {
	return fmt.Sprintf("Server key not found for prefix %d.", err.Prefix)
}

func (err *ErrVersionNotSupported) Error() string {
	return fmt.Sprintf("Version not supported: %d.", err.V)
}

// Message represents the context required for authorization.
type Message struct {
	HostIDType string // type of identity
	HostID     string // identity of the target (e.g. hostname, serial number, etc.)
	Action     string // action that is being authorized
}

// Construct returns a message from a Message according to the format: [<hostid-type>:]<hostid>[/<action>].
// URL escaping is optional.
func (m *Message) Construct(esc bool) []byte {
	hostIDType := m.HostIDType
	hostID := m.HostID
	if esc {
		hostIDType = escape(hostIDType)
		hostID = escape(hostID)
	}
	action := ""

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
type Handshake struct {
	Prefix           byte            // either service key id or its last 7 bits of the first byte
	UserKey          glome.PublicKey // user's public ephemeral key
	MessageTagPrefix []byte          // Prefix of a tag calculated under Message
}

// URLResponse represents the context required for the construction of the URL.
type URLResponse struct {
	V             byte          // URL format V (currently always 1)
	HandshakeInfo Handshake     // handshake info including Prefix, user's public key and message tag Prefix
	Msg           Message       // message info including host and action
	d             *glome.Dialog // glome.Dialog for the tag managing
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
		// TODO(#60): Fix this up once there is clarify on key Prefix usage.
		prefix = serviceKey[0] & 0x7f
	} else {
		prefix = serviceKeyID & 0x7f
	}
	userPublic, err := userKey.Public()
	if err != nil {
		return nil, err
	}
	r.HandshakeInfo = Handshake{prefix, *userPublic, r.Tag(tagLen)}

	return &r, nil
}

// ValidateAuthCode checks if the received tag corresponding to the tag calculated under message constructed from the Message.
func (r *URLResponse) ValidateAuthCode(tag []byte) bool {
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

// Client implements the client-side of the glome-login protocol. Should be constructed under NewClient constructor.
type Client struct {
	ServerKey   glome.PublicKey  // server's public key
	UserKey     glome.PrivateKey // user's private key
	ServerKeyID uint8            // server's key id
	TagLen      uint             // length of a tag to be sent to the server. Should be in [0..glome.MaxTagLength] range.
	response    *URLResponse     // URL challenge
}

// NewClient is a Client constructor. Sets Client.ServerKey, Client.UserKey, Client.ServerKeyID, Client.TagLen
// to the corresponding values and Client.response to nil.
func NewClient(sk glome.PublicKey, uk glome.PrivateKey, sID uint8, tagLen uint) *Client {
	return &Client{sk, uk, sID, tagLen, nil}
}

// Construct returns a request to the server according to the format: /v<V>/<glome-handshake>[/<message>]/.
func (c *Client) Construct(V byte, hostIDType string, hostID string, action string) (string, error) {
	r, err := NewResponse(c.ServerKeyID, c.ServerKey, c.UserKey, V, hostIDType, hostID, action, c.TagLen)
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

// ValidateAuthCode checks if the received tag corresponding to the tag calculated under message constructed from the Message.
// Returns ErrResponseNotInitialized if the Client.response is not initialized.
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

// Response is a getter for Client.response.
func (c *Client) Response() *URLResponse {
	return c.response
}

// Server implements the server-side of the glome-login protocol.
type Server struct {
	// Fetch the server's private key given a version ID. Caller is responsible
	// for not modifying the returned private key. If the key is authoritatively
	// found to not exist for a given version it is expected that (nil, nil) is
	// returned.
	KeyFetcher func(uint8) (*glome.PrivateKey, error)
}

// ParseURLResponse parses the url, checks whether it is formed correctly and validates the client's tag, received from the URL.
// Returns ErrInvalidURLFormat if the URL is malformed, ErrServerKeyNotFound is there is no key corresponding to prefix,
// ErrIncorrectTag if the client's tag is invalid.
func (s *Server) ParseURLResponse(url string) (*URLResponse, error) {
	response := URLResponse{}

	names := validURLPrefix.SubexpNames()[1:]        // as "The name for the first sub-expression is names[1].."
	parsed := validURLPrefix.FindStringSubmatch(url) // save first element (full substring) to be trimmed later in url
	if parsed == nil {
		return nil, &ErrInvalidURLFormat{url}
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
		return nil, err
	}
	if sPrivKey == nil {
		return nil, &ErrServerKeyNotFound{handshake.Prefix}
	}
	response.d, err = sPrivKey.TruncatedExchange(&handshake.UserKey, 1)
	if err != nil {
		return nil, err
	}

	message := strings.TrimPrefix(url, parsed[0])
	if len(message) == 0 { // <message> is empty
		if len(response.HandshakeInfo.MessageTagPrefix) == 0 {
			return &response, nil
		}
		return nil, ErrIncorrectTag
	}
	if message[len(message)-1] == '/' { // check last slash
		parsed, err := parseMsg(strings.TrimSuffix(message, "/"))
		if err != nil {
			return nil, err
		}
		response.Msg = *parsed

		if len(response.HandshakeInfo.MessageTagPrefix) == 0 {
			return &response, nil
		}
		if response.ValidateAuthCode(response.HandshakeInfo.MessageTagPrefix) != true {
			return nil, ErrIncorrectTag
		}
		return &response, nil
	}

	return nil, &ErrInvalidURLFormat{url}
}

// parseVersion returns the parsed version of the URL format version. Returns ErrVersionNotSupported,
// if the version is not supported.
func parseVersion(v string) (byte, error) {
	parsed, err := strconv.Atoi(v[1:])
	if err != nil {
		return 0, err
	}
	if parsed != 1 { // current parsed
		return 0, &ErrVersionNotSupported{parsed}
	}

	return byte(parsed), nil
}

// parseHandshake returns the parsed V of the URL handshake.
// The handshake should satisfy the following format:
//		glome-handshake := base64url(
//    		<prefix-type>
//    		<prefix7>
//    		<eph-key>
//    		[<prefixN>]
//  	).
// Returns ErrInvalidHandshakeLen if the tag length is less than minHandshakeLen,
// ErrInvalidPrefixType if prefix-type is different from 0,
// glome.ErrInvalidTagSize if the tag length is bigger than glome.MaxTagSize.
func parseHandshake(handshake string) (*Handshake, error) {
	dHandshake, err := base64.URLEncoding.DecodeString(handshake)
	if err != nil {
		return nil, err
	}
	if len(dHandshake) < minHandshakeLen {
		return nil, ErrInvalidHandshakeLen
	}

	prefix := dHandshake[0]
	if prefix>>7 != 0 { // check Prefix-type
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

// parseMsg returns the parsed V of the URL message.
// The message should satisfy the following format: [<hostid-type>:]<hostid>[/<action>].
func parseMsg(hostAndAction string) (*Message, error) {
	var hostIDType, hostID, action string

	split := strings.SplitN(hostAndAction, "/", 2)
	host, err := url.QueryUnescape(split[0])
	if err != nil {
		return nil, err
	}

	var h = strings.SplitN(host, ":", 2)
	if len(h) == 2 { // <hostid-type> is present
		hostIDType = h[0]
		hostID = h[1]
	} else {
		hostID = h[0]
	}

	if len(split) == 2 { // <action> is present
		action = split[1]
	}

	return &Message{hostIDType, hostID, action}, nil
}
