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

package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os/exec"

        "github.com/google/glome/go/glome"
        "github.com/google/glome/go/login/server"

	"gopkg.in/yaml.v2"
)

// keyConfig is an auxiliary type for communication with go-yaml library.
type keyConfig struct {
	Key   string
	Index uint8
}

// readKeys reads keys from provided package
func readKeys(filename string) (map[string]keyConfig, error) {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Error loading key file %q: %v", filename, err)
	}

	keys := make(map[string]keyConfig)
	err = yaml.Unmarshal([]byte(yamlFile), &keys)
	if err != nil {
		return nil, fmt.Errorf("Error parsing key file %q as YAML: %v", filename, err)
	}

	return keys, nil
}

// updateKeys update the keys read by readKeys
func updateKeys(unformatedKeys map[string]keyConfig, b *server.LoginServer) error {
	var formatedKeys []server.PrivateKey
	for _, k := range unformatedKeys {
		key, err := hex.DecodeString(k.Key)
		if err != nil {
			return fmt.Errorf("can't decode string %s into private key: %v", k.Key, err)
		}

		p, err := glome.PrivateKeyFromSlice(key)
		if err != nil {
			return fmt.Errorf("can't decode string %s into private key: %v", k.Key, err)
		}
		formatedKeys = append(formatedKeys, server.PrivateKey{Value: *p, Index: k.Index})
	}
	b.Keys.DropAllReplace(formatedKeys)
	return nil
}

func BinaryBasedAuthorizer(path string) (server.AuthorizerFunc, error) {
	p, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("Could not find binary in %#v", path)
	}

	return server.AuthorizerFunc(func(user string, hostID string, hostIDType string, action string) (bool, error) {
		cmd := exec.Command(p)
		cmd.Stdin = nil
		cmd.Env = []string{
			fmt.Sprintf("USER=%s", user),
			fmt.Sprintf("HOSTID=%s", hostID),
			fmt.Sprintf("HOSTIDTYPE=%s", hostIDType),
			fmt.Sprintf("ACTION=%s", action),
		}
		var out bytes.Buffer
		cmd.Stdout = &out

		err = cmd.Run()
		if err == nil {
			return true, nil
		} else {
			return false, nil
		}
	}), nil
}
