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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/glome/go/glome"
	"github.com/google/go-cmp/cmp"
)

const (
	sampleConfigPath = "../../login"
)

func TestParseKeyValue(t *testing.T) {
	tcs := []struct {
		line      string
		wantKey   string
		wantValue string
		wantErr   bool
	}{{
		line:      "a = b",
		wantKey:   "a",
		wantValue: "b",
	}, {
		line:      "a=b",
		wantKey:   "a",
		wantValue: "b",
	}, {
		line:      "some-hyphenated-key\t\t=some value with spaces",
		wantKey:   "some-hyphenated-key",
		wantValue: "some value with spaces",
	}}
	for _, tc := range tcs {
		t.Run(tc.line, func(t *testing.T) {
			gotKey, gotValue, err := parseKeyValue(tc.line)
			if tc.wantErr != (err != nil) {
				t.Fatalf("parseKeyValue: %v (want err? %v)", err, tc.wantErr)
			}

			if gotKey != tc.wantKey {
				t.Errorf("parseKeyValue: key = %q; want %q", gotKey, tc.wantKey)
			}
			if gotValue != tc.wantValue {
				t.Errorf("parseKeyValue: key = %q; want %q", gotValue, tc.wantValue)
			}
		})
	}
}

func TestParseError(t *testing.T) {
	tcs := []struct {
		name       string
		err        ParseError
		wantString string
	}{{
		name:       "descriptionless",
		err:        ParseError{1337, BadSectionName, ""},
		wantString: "config file parsing failed in line 1337 (bad section header line)",
	}, {
		name:       "with description",
		err:        ParseError{1337, BadSectionName, "something went wrong"},
		wantString: "config file parsing failed in line 1337 (bad section header line: something went wrong)",
	}}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			gotString := tc.err.Error()
			if gotString != tc.wantString {
				t.Errorf("tc.err.Error() = %q; want %q", gotString, tc.wantString)
			}
		})
	}
}

func TestDefaultSectionUndefined(t *testing.T) {
	oldSectionAssigners := sectionAssigners
	defer func() { sectionAssigners = oldSectionAssigners }()

	sectionAssigners = nil

	wantErr := ParseError{1, UnknownSection, "default"}
	_, err := Parse(strings.NewReader("test = a\n"))
	if diff := cmp.Diff(wantErr, err); diff != "" {
		t.Errorf("Parse: got diff (-want +got)\n%v", diff)
	}
}

func TestParseConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  string
		options []OptionFunc
		want    *Config
	}{{
		name: "insecure config",
		config: `
; Semicolon comments are allowed
# As are hash comments

auth-delay = 20
input-timeout = 10
config-path = /etc/glome/glome.cfg
ephemeral-key = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
min-authcode-len = 5
host-id = myhost.corp.big.example
host-id-type = bigcorp-machine-identifier
login-path = /opt/bigcorp/bin/login
disable-syslog = 0
print-secrets = yes
timeout = 60
verbose = true

[service]
prompt = glome://
key-version = 27
public-key = glome-v1 aqA9yqe1RXoOT6HrmCbF40wVUhYp50FYZR9q8_X5KF4=
`,
		options: []OptionFunc{AllowInsecureOptions},
		want: &Config{
			AuthDelay:    20,
			InputTimeout: 10,
			ConfigPath:   "/etc/glome/glome.cfg",
			EphemeralKey: glome.PrivateKey{
				0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
				0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
			},
			MinAuthcodeLen: 5,
			HostID:         "myhost.corp.big.example",
			HostIDType:     "bigcorp-machine-identifier",
			LoginPath:      "/opt/bigcorp/bin/login",
			DisableSyslog:  false,
			PrintSecrets:   true,
			Timeout:        60,
			Verbose:        true,

			ServiceConfig: ServiceConfig{
				Prompt:     "glome://",
				KeyVersion: 27,
				PublicKey: glome.PublicKey{
					0x6a, 0xa0, 0x3d, 0xca, 0xa7, 0xb5, 0x45, 0x7a, 0x0e, 0x4f, 0xa1,
					0xeb, 0x98, 0x26, 0xc5, 0xe3, 0x4c, 0x15, 0x52, 0x16, 0x29, 0xe7,
					0x41, 0x58, 0x65, 0x1f, 0x6a, 0xf3, 0xf5, 0xf9, 0x28, 0x5e,
				},
			},
		},
	}, {
		name: "config",
		config: `
; Semicolon comments are allowed
# As are hash comments

auth-delay = 20
input-timeout = 10
config-path = /etc/glome/glome.cfg
min-authcode-len = 5
host-id = myhost.corp.big.example
host-id-type = bigcorp-machine-identifier
login-path = /opt/bigcorp/bin/login
disable-syslog = 0
print-secrets = no
timeout = 60
verbose = true

[service]
prompt = glome://
key-version = 27
public-key = glome-v1 aqA9yqe1RXoOT6HrmCbF40wVUhYp50FYZR9q8_X5KF4=
`,
		want: &Config{
			AuthDelay:      20,
			InputTimeout:   10,
			ConfigPath:     "/etc/glome/glome.cfg",
			MinAuthcodeLen: 5,
			HostID:         "myhost.corp.big.example",
			HostIDType:     "bigcorp-machine-identifier",
			LoginPath:      "/opt/bigcorp/bin/login",
			DisableSyslog:  false,
			PrintSecrets:   false,
			Timeout:        60,
			Verbose:        true,

			ServiceConfig: ServiceConfig{
				Prompt:     "glome://",
				KeyVersion: 27,
				PublicKey: glome.PublicKey{
					0x6a, 0xa0, 0x3d, 0xca, 0xa7, 0xb5, 0x45, 0x7a, 0x0e, 0x4f, 0xa1,
					0xeb, 0x98, 0x26, 0xc5, 0xe3, 0x4c, 0x15, 0x52, 0x16, 0x29, 0xe7,
					0x41, 0x58, 0x65, 0x1f, 0x6a, 0xf3, 0xf5, 0xf9, 0x28, 0x5e,
				},
			},
		},
	}} {
		got, err := Parse(strings.NewReader(tc.config), tc.options...)
		if err != nil {
			t.Errorf("%v: Parse: %v", tc.name, err)
			continue
		}

		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("%v: Parse: got diff (-want, +got):\n%s", tc.name, diff)
		}
	}
}

func TestParseConfig_Errors(t *testing.T) {
	tcs := []struct {
		name      string
		config    string
		options   []OptionFunc
		wantError ParseErrorType
	}{{
		name:      "invalid section header",
		config:    "[",
		wantError: BadSectionName,
	}, {
		name:      "empty section name",
		config:    "[]",
		wantError: BadSectionName,
	}, {
		name:      "unknown section",
		config:    "[this-section-does-not-exist]",
		wantError: UnknownSection,
	}, {
		name:      "invalid config line",
		config:    "hello",
		wantError: BadKeyValue,
	}, {
		name:      "invalid config line with spaces",
		config:    "hello a b c",
		wantError: BadKeyValue,
	}, {
		name:      "missing key",
		config:    "= true",
		wantError: BadKeyValue,
	}, {
		name:      "unknown key in default section",
		config:    "unknown-key = true",
		wantError: UnknownKeyInDefault,
	}, {
		name: "unknown key in service section",
		config: `
[service]
unknown-key = true
`,
		wantError: UnknownKeyInService,
	}, {
		name:      "missing value for boolean",
		config:    "verbose =",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for boolean",
		config:    "verbose = invalid",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for positive int (negative)",
		config:    "auth-delay = -1",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for positive int (garbage)",
		config:    "auth-delay = invalid",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for key version (negative)",
		config:    "[service]\nkey-version = -1",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for key version (garbage)",
		config:    "[service]\nkey-version = invalid",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for key version (too big)",
		config:    "[service]\nkey-version = 128",
		wantError: InvalidValueForKey,
	}, {
		name:      "insecure option specified without AllowInsecureOptions",
		config:    "ephemeral-key = anything",
		wantError: InsecureOptionsProhibited,
	}, {
		name:      "print-secrets specified without AllowInsecureOptions",
		config:    "print-secrets = true",
		wantError: InsecureOptionsProhibited,
	}, {
		name:      "invalid value for private key (garbage)",
		options:   []OptionFunc{AllowInsecureOptions},
		config:    "ephemeral-key = invalid",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for private key (too short)",
		config:    "ephemeral-key = aa",
		options:   []OptionFunc{AllowInsecureOptions},
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for legacy public key (garbage)",
		config:    "[service]\nkey = invalid",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for legacy public key (too short)",
		config:    "[service]\nkey = aa",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for public key (garbage)",
		config:    "[service]\npublic-key = invalid",
		wantError: InvalidValueForKey,
	}, {
		name:      "invalid value for public key (too short)",
		config:    "[service]\npublic-key = glome-v1 aGkK",
		wantError: InvalidValueForKey,
	}}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.config), tc.options...)
			if err == nil {
				t.Fatalf("Parse didn't return an error; I expected one")
			}

			cpe, ok := err.(ParseError)
			if !ok {
				t.Fatalf("Parse: %v (wanted a ParseError)", err)
			}

			if cpe.ErrorType != tc.wantError {
				t.Errorf("Parse: %v (error type was %q; want %q)", err, cpe.ErrorType, tc.wantError)
			}
		})
	}
}

func TestParseConfig_InTreeSamples(t *testing.T) {
	names, err := filepath.Glob(filepath.Join(sampleConfigPath, "*.cfg"))
	if err != nil {
		t.Fatalf("finding sample config files: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("no sample config files found in //login/*.cfg")
	}

	for _, name := range names {
		t.Run(filepath.Base(name), func(t *testing.T) {
			f, err := os.Open(name)
			if err != nil {
				t.Fatalf("os.Open(%q): %v", name, err)
			}
			defer f.Close()

			if _, err := Parse(f, AllowInsecureOptions); err != nil {
				t.Errorf("Parse: %v", err)
			}
		})
	}
}
