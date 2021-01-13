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
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/glome/go/glome"
	"github.com/google/glome/go/login/server"

	"github.com/spf13/cobra"
)

var (
	keys        string
	addr        string
	script      string
	userHeader  string
	responseLen int

	runCmd = &cobra.Command{
		Use:   "run [-a <addr>] [-k <keyfile>] [-s <lua-script>]",
		Short: "Run command creates a LoginServer that listen and serve in provided address.",
		Long: `Run implements the server side of the glome-login protocol.
Visit github.com/google/glome for more information on the protocol.

This program implements the basic functionalities of the glome-server, using the glome-framework.
It requires the flags -a, -k and -s to be provided to properly work. For more information, visit`,
		PreRun: PreRun,
		Run:    Run,
	}
)

func PreRun(cmd *cobra.Command, args []string) {
	if keys == "" || addr == "" || script == "" {
		fmt.Println(`Please, provide key file, authorization script and address.
For more information read --help option.`)
		os.Exit(0)
	}
}

func Run(cmd *cobra.Command, args []string) {
	authorizer, err := BinaryBasedAuthorizer(script)
	if err != nil {
		log.Fatalf("Error Reading Authorization binary: %v", err)
	}

	srv, err := server.NewLoginServer(authorizer)
	if err != nil {
		log.Fatalf("Error creating new server: %v", err)
	}

	formatedKeys, err := readKeys(keys)
	if err != nil {
		log.Fatalf("Error reading key file: %v", err)
	}

	err = updateKeys(formatedKeys, srv)
	if err != nil {
		log.Fatalf("Error Updating key manager: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	go handleSignals(sig, srv)

	log.Fatalln(http.ListenAndServe(addr, srv))
}

func init() {
	runCmd.Flags().StringVarP(&keys, "key", "k", "", "[mandatory] location of the key file")
	runCmd.Flags().StringVarP(&addr, "addr", "a", "", "[mandatory] address to serve")
	runCmd.Flags().StringVarP(&script, "script", "s", "", "[mandatory] location of authorization script binary")
	runCmd.Flags().StringVarP(&userHeader, "user-header", "u", "authenticated-user",
		"user header from which to read the user information")
	runCmd.Flags().IntVarP(&responseLen, "response-length", "r", glome.MaxTagSize,
		"size in bytes of the response token, should be in range [1-32]")
}

func handleSignals(sig chan os.Signal, srv *server.LoginServer) {
	for {
		s := <-sig
		switch s {
		case syscall.SIGHUP:
			newAuthorizer, err := BinaryBasedAuthorizer(script)
			if err != nil {
				log.Printf("Error Reading Authorization binary: %v", err)
			}
			srv.Authorizer(newAuthorizer)

			formatedKeys, err := readKeys(keys)
			if err != nil {
				log.Printf("Error reading key file: %v", err)
				continue
			}

			err = updateKeys(formatedKeys, srv)
			if err != nil {
				log.Printf("Error Updating key manager: %v", err)
			}
		}
	}
}
