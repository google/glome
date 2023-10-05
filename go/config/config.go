// Copyright 2023 Google LLC
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

package config

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/glome/go/glome"
)

// Config represents the supported GLOME login settings.
type Config struct {
	AuthDelay      int
	InputTimeout   int
	ConfigPath     string
	EphemeralKey   glome.PrivateKey
	MinAuthcodeLen int
	HostID         string
	HostIDType     string
	LoginPath      string
	DisableSyslog  bool
	PrintSecrets   bool
	Timeout        int
	Verbose        bool

	ServiceConfig ServiceConfig
}

// ServiceConfig contains GLOME settings from the [service] configuration section.
type ServiceConfig struct {
	PublicKey  glome.PublicKey
	KeyVersion int
	Prompt     string
}

// ParseErrorType represents different classes of things that can happen during parsing a GLOME configuration.
type ParseErrorType string

const (
	// BadSectionName indicates that a line could not be parsed as a configuration section header.
	BadSectionName ParseErrorType = "bad section header line"

	// BadKeyValue indicates that a line could not be parsed as a key=value.
	BadKeyValue ParseErrorType = "bad key/value line"

	// UnknownSection indicates that the section name is unknown.
	UnknownSection ParseErrorType = "unknown section name"

	// UnknownKeyInDefault indicates that the configuration key in the default section is unknown.
	UnknownKeyInDefault ParseErrorType = "unknown key in default section"

	// UnknownKeyInService indicates that the configuration key in the service section is unknown.
	UnknownKeyInService ParseErrorType = "unknown key in 'service' section"

	// InvalidValueForKey indicates that parsing the configuration value failed.
	InvalidValueForKey ParseErrorType = "invalid value for key"

	// InsecureOptionsProhibited indicates that the configuration specifies a key marked as "insecure", which is not allowed without AllowInsecureOptions.
	InsecureOptionsProhibited ParseErrorType = "insecure option prohibited"
)

// ParseError represents an error that happened while parsing a GLOME configuration.
type ParseError struct {
	LineNum     int
	ErrorType   ParseErrorType
	Description string
}

// Error satisfies the Go `error` interface.
func (e ParseError) Error() string {
	descriptionSeparator := ""
	if e.Description != "" {
		descriptionSeparator = ": "
	}
	return fmt.Sprintf("config file parsing failed in line %d (%s%s%s)", e.LineNum, e.ErrorType, descriptionSeparator, e.Description)
}

var (
	sectionAssigners = map[string]func(cfg *Config, lineNum int, key, value string, o *options) error{
		"default": assignDefaultSection,
		"service": assignServiceSection,
	}
)

type options struct {
	AllowInsecureOptions bool
}

// OptionFunc modifies the available options.
type OptionFunc func(o *options)

// AllowInsecureOptions enables the parsed config file to include options that are intended for testing only and should not be used in production.
func AllowInsecureOptions(o *options) {
	o.AllowInsecureOptions = true
}

// Parse parses a GLOME ini-style configuration file to a Config struct.
func Parse(r io.Reader, opts ...OptionFunc) (*Config, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	s := bufio.NewScanner(r)
	currentSection := "default"
	lineNum := 0
	cfg := new(Config)
	for s.Scan() {
		lineNum++
		txt := strings.TrimSpace(s.Text())
		switch {
		case len(txt) == 0, txt[0] == '#', txt[0] == ';':
			// Purely whitespace, or a comment.
			continue
		case txt[0] == '[':
			// Section header
			end := strings.IndexByte(txt, ']')
			if end == -1 {
				return nil, ParseError{lineNum, BadSectionName, "couldn't find closing ]"}
			}
			currentSection = txt[1:end]
			if len(currentSection) == 0 {
				return nil, ParseError{lineNum, BadSectionName, "section name was empty"}
			}
			if _, ok := sectionAssigners[currentSection]; !ok {
				return nil, ParseError{lineNum, UnknownSection, currentSection}
			}
		default:
			// Key value config option.
			key, value, err := parseKeyValue(txt)
			if err != nil {
				return nil, ParseError{lineNum, BadKeyValue, err.Error()}
			}

			assignValue, ok := sectionAssigners[currentSection]
			if !ok {
				// We shouldn't end up here since we validate section names as we assign them.
				// However, just in case...
				return nil, ParseError{lineNum, UnknownSection, currentSection}
			}
			if err := assignValue(cfg, lineNum, key, value, o); err != nil {
				return nil, err
			}
		}

	}
	return cfg, nil
}

func assignDefaultSection(cfg *Config, lineNum int, key, value string, o *options) error {
	var err error
	switch key {
	case "auth-delay":
		err = interpretPositiveInt(value, &cfg.AuthDelay)
	case "input-timeout":
		err = interpretPositiveInt(value, &cfg.InputTimeout)
	case "config-path":
		cfg.ConfigPath = value
	case "ephemeral-key":
		if !o.AllowInsecureOptions {
			return ParseError{lineNum, InsecureOptionsProhibited, key}
		}
		err = interpretPrivateKey(value, hex.DecodeString, &cfg.EphemeralKey)
	case "min-authcode-len":
		err = interpretPositiveInt(value, &cfg.MinAuthcodeLen)
	case "host-id":
		cfg.HostID = value
	case "host-id-type":
		cfg.HostIDType = value
	case "login-path":
		cfg.LoginPath = value
	case "disable-syslog":
		err = interpretBool(value, &cfg.DisableSyslog)
	case "print-secrets":
		err = interpretBool(value, &cfg.PrintSecrets)
		if !o.AllowInsecureOptions && cfg.PrintSecrets {
			// We only judge print-secrets as insecure if it's true.
			return ParseError{lineNum, InsecureOptionsProhibited, key}
		}
	case "timeout":
		err = interpretPositiveInt(value, &cfg.Timeout)
	case "verbose":
		err = interpretBool(value, &cfg.Verbose)
	default:
		return ParseError{lineNum, UnknownKeyInDefault, key}
	}
	if err != nil {
		return ParseError{lineNum, InvalidValueForKey, fmt.Sprintf("section: default; key: %s; provided value: %s; %s", key, value, err.Error())}
	}
	return nil
}

func assignServiceSection(cfg *Config, lineNum int, key, value string, o *options) error {
	var err error
	switch key {
	case "key":
		// Provided for backwards-compatibility only.
		// TODO: to be removed in 1.0.
		err = interpretPublicKey(value, hex.DecodeString, &cfg.ServiceConfig.PublicKey)
	case "url-prefix":
		// Provided for backwards-compatibility only.
		// TODO: to be removed in 1.0.
		cfg.ServiceConfig.Prompt = value + "/"
	case "key-version":
		err = interpretKeyVersion(value, &cfg.ServiceConfig.KeyVersion)
	case "prompt":
		cfg.ServiceConfig.Prompt = value
	case "public-key":
		err = interpretPublicKey(value, decodeGLOMEPublicKey, &cfg.ServiceConfig.PublicKey)
	default:
		return ParseError{lineNum, UnknownKeyInService, key}
	}
	if err != nil {
		return ParseError{lineNum, InvalidValueForKey, fmt.Sprintf("section: service; key: %s; provided value: %s; %s", key, value, err.Error())}
	}
	return nil
}

// parseKeyValue parses a `key = value` string, where whitespace has been pre-removed from the head and tail.
func parseKeyValue(line string) (key, value string, err error) {
	// Key is the line up to the first space or =.
	keyEnd := strings.IndexFunc(line, func(r rune) bool {
		return unicode.IsSpace(r) || r == '='
	})
	if keyEnd == -1 {
		return "", "", fmt.Errorf("couldn't find = key/value separator")
	}
	key = line[:keyEnd]
	if key == "" {
		return "", "", fmt.Errorf("empty key is invalid")
	}
	line = line[keyEnd:]

	// Value is the line starting from the first non-space after =.
	valueStart := strings.IndexFunc(line, func(r rune) bool {
		return !unicode.IsSpace(r) && r != '='
	})
	if valueStart == -1 {
		// Possibly an empty value.
		valueStart = len(line)
	}
	separator := line[:valueStart]
	value = line[valueStart:]

	if strings.IndexByte(separator, '=') == -1 {
		return "", "", fmt.Errorf("couldn't find = key/value separator")
	}

	return key, value, nil
}

// interpretBool parses a boolean value in the same manner as GLOME's C implementation.
func interpretBool(value string, b *bool) error {
	switch value {
	case "true", "yes", "on", "1":
		*b = true
		return nil
	case "false", "no", "off", "0":
		*b = false
		return nil
	}
	return fmt.Errorf("invalid boolean value %q", value)
}

// interpretPositiveInt parses a positive integer.
func interpretPositiveInt(value string, i *int) error {
	v, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("expected positive int, got %d", v)
	}
	*i = v
	return nil
}

// interpretPrivateKey parses a encoded private key.
func interpretPrivateKey(value string, decoder func(s string) ([]byte, error), k *glome.PrivateKey) error {
	bs, err := decoder(value)
	if err != nil {
		return err
	}
	pk, err := glome.PrivateKeyFromSlice(bs)
	if err != nil {
		return err
	}
	copy(k[:], pk[:])
	return nil
}

// interpretPublicKey parses a encoded public key.
func interpretPublicKey(value string, decoder func(s string) ([]byte, error), k *glome.PublicKey) error {
	bs, err := decoder(value)
	if err != nil {
		return err
	}
	pk, err := glome.PublicKeyFromSlice(bs)
	if err != nil {
		return err
	}
	copy(k[:], pk[:])
	return nil
}

// interpretKeyVersion parses a key version.
func interpretKeyVersion(value string, i *int) error {
	v, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	if v < 0 || v > 127 {
		return fmt.Errorf("expected int in range [0..127], got %d", v)
	}
	*i = v
	return nil
}

const glomeV1PublicKeyPrefix = "glome-v1 "

// decodeGLOMEPublicKey decodes an RFD002-encoded GLOME public key to a byte slice.
func decodeGLOMEPublicKey(value string) ([]byte, error) {
	if !strings.HasPrefix(value, glomeV1PublicKeyPrefix) {
		return nil, fmt.Errorf("missing %q prefix", glomeV1PublicKeyPrefix)
	}
	value = value[len(glomeV1PublicKeyPrefix):]
	return base64.URLEncoding.DecodeString(value)
}
