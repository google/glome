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

// Package server implements GLOME-login server framework.
package server

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/glome/go/login"
)

const (
	// MaxResponseSize is the maximum size in characaters of the response token
	MaxResponseSize = 44 // 32 bytes base64 encoded
)

// ErrInvalidResponseLen denotes that response length provided is invalid. ResponseLen
// should be in range {1,...,MaxResponseSize}
type ErrInvalidResponseLen struct {
	ResponseLen uint8
}

func (e ErrInvalidResponseLen) Error() string {
	return fmt.Sprintf("ResponseLen should be in range {1,...,%v}, got %v", MaxResponseSize, e.ResponseLen)
}

// Authorizer responds to an authorization request. The method
// GrantLogin returns whether an user is allowed to perform a given action on a host.
//
// Some considerations need to be held while implementing this interface:
// - Allow should consider that an empty string as command is a correct input.
// - If no user can be obtained from request metadata, an empty string is to be
// passed as default value.
// - Both hostIDType and hostID can be empty. Whether this refer to a default value
// or not is to be user configurable.
// - returned boolean will be considered even if an error is returned.
type Authorizer interface {
	GrantLogin(user string, hostID string, hostIDType string, action string) (bool, error)
}

// AuthorizerFunc type is an adapter to allow the use of ordinary functions as an Authorizer.
type AuthorizerFunc func(user string, hostID string, hostIDType string, action string) (bool, error)

// GrantLogin calls a(user, hostID, hostIDType, action)
func (a AuthorizerFunc) GrantLogin(user string, hostID string, hostIDType string, action string) (bool, error) {
	return a(user, hostID, hostIDType, action)
}

// LoginServer is a framework that can be used to implement servers for glome-login.
type LoginServer struct {
	// Keys manages the keys used by the server.
	Keys *KeyManager

	auth        Authorizer
	authLock    sync.RWMutex
	loginParser *login.Server

	responseLen uint8
	userHeader  string
}

// Authorizer replaces the server Authorizer with a new one provided, in a secure way for concurrency.
func (s *LoginServer) Authorizer(a Authorizer) {
	s.authLock.Lock()
	s.auth = a
	s.authLock.Unlock()
}

// NewLoginServer creates a new server with provided Authorizer and, optionally, selected options.
func NewLoginServer(a Authorizer, options ...func(*LoginServer) error) (*LoginServer, error) {
	srv := LoginServer{
		auth:        a,
		Keys:        NewKeyManager(),
		responseLen: MaxResponseSize,
		userHeader:  "authenticated-user",
	}
	srv.loginParser = srv.newLoginParser()

	for _, option := range options {
		if err := option(&srv); err != nil {
			return nil, err
		}
	}

	return &srv, nil
}

// ResponseLen is an option to be provided to NewServer on creation. Its sets the size of response
// to provided length. the size is measured in number of characters in base64. Return
// ErrInvalidResponseLen if provided length is not in {1,..,MaxResponseSize}. If not set,
// defaults to MaxResponseSize.
func ResponseLen(length uint8) func(srv *LoginServer) error {
	return func(srv *LoginServer) error {
		if !(0 < length && length <= MaxResponseSize) {
			return ErrInvalidResponseLen{ResponseLen: length}
		}
		srv.responseLen = length
		return nil
	}
}

// UserHeader is an option to be provided to NewServer on creation. It sets the name of the
// HTTP header from which to read the user id. It defaults to "authenticated-user".
func UserHeader(s string) func(srv *LoginServer) error {
	return func(srv *LoginServer) error {
		srv.userHeader = s
		return nil
	}
}

func (s *LoginServer) newLoginParser() *login.Server {
	return &login.Server{KeyFetcher: s.Keys.keyFetcher()}
}

// ServeHTTP implements http.Handler interface:
// - On "/": List server service keys.
// - On a glome login URL: Return a login token or an error message.
func (s *LoginServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		s.printServerKeys(w)
		return
	}

	user := r.Header.Get(s.userHeader)

	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}

	response, err := s.loginParser.ParseURLResponse(path)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	s.printToken(w, response, user)
}

// Auxiliary function to print login token on response writer.
func (s *LoginServer) printToken(w http.ResponseWriter, r *login.URLResponse, user string) {
	s.authLock.RLock()
	allowed, err := s.auth.GrantLogin(user, r.Msg.HostID, r.Msg.HostIDType,
		r.Msg.Action)
	s.authLock.RUnlock()

	if !allowed {
		if err != nil {
			http.Error(w, err.Error(), 403)
		} else {
			http.Error(w, "unauthorized action", 403)
		}

		return
	}

	responseToken := r.EncToken()[:s.responseLen]
	fmt.Fprintln(w, responseToken)
}

// Auxiliary function that prints service keys.
func (s *LoginServer) printServerKeys(w http.ResponseWriter) {

	fmt.Fprintf(w, "List of server keys\n")
	fmt.Fprintf(w, "-------------------\n")
	fmt.Fprintf(w, "Index\tValue\n")
	for _, key := range s.Keys.ServiceKeys() {
		fmt.Fprintf(w, "%v\t%v\n", key.Index, hex.EncodeToString(key.Value[:]))
	}
}
