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

// This package shows a simple configuration based on the use of sets to
// decide if a user has access to a machine, following some simple rules:
//   - A special user can run functions from the command table in any machine.
//   - Each machine has a list of paired users that can run commands in command table.
//   - All other commands are blocked.
package main

import (
	"os"
)

var (
	// GeneralMachines store the map of machines to the set users. Machines follows syntax "[<host-type>:]<host>"
	Machines = map[string]map[string]bool{
		"my-server.local":                     Set("", "default-user"),
		"serial-number:1234567890=ABCDFGH/#?": Set("", "default-user"),
	}
	// SpecialUser stores the set of special users
	SpecialUser = Set("admin")
	// Commands stores the set of valid actions
	Commands = Set("shell/root", "reboot")
)

// Sugar syntax for set
func Set(strs ...string) map[string]bool {
	set := make(map[string]bool)
	for _, str := range strs {
		set[str] = true
	}
	return set
}

// Authorization Function
// Note that, in the example, empty action is not allowed, but empty user is.
// This means that default user is allow, while default action isn't.
func auth(user string, hostID string, hostIDType string, action string) bool {
	if Commands[action] {
		machine := hostID // Format the syntax "[<host-type>:]<host>"
		if hostIDType != "" {
			machine = hostIDType + ":" + hostID
		}
		if SpecialUser[user] || Machines[machine][user] {
			return true
		}
	}
	return false
}

func main() {
	if auth(os.Getenv("USER"), os.Getenv("HOSTID"), os.Getenv("HOSTIDTYPE"), os.Getenv("ACTION")) {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
