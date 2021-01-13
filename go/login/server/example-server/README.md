# GLOME Server Example

Run implements the server side of the glome-login protocol. Look at(this)[https://github.com/google/glome/blob/master/docs/glome-login.md] for more information on the login protocol.

This program implements the basic functionalities of the glome-server, using the glome-framework. It requires the flags `-a`, `-k` and `-s` to be provided to run. For example:

```
loginserver -k key-file.yml -a 127.0.0.1:8000 -s binary-file
```

## CLI
Based on the backend - framework, an actual working server is planned to be done. This server will be developed using exec for the authorization function and cobra for the implementation of the CLI.

The server provides two commands:
- run: run the server
- help: print the help string


## Configuration Files

### Key File 
The server use a yaml file from which to read the keys. In the yaml file there will be some structures each one representing one key. This can be named arbitrarily.On each one of this structures it will be two fields:
- key: stores the key in hexadecimal:
   - Should not include “0x” prefix
   - Has to be 64 characters long

- Index: stores the index
  - Can be in any format accepted in golang as integer.
  - Should be in range [0-127]. Otherwise the server will fail on initialization. 

#### Authorization Script
The server accepts a binary to be provided with the authentication. This binary:
 - Receives the parameters USER, HOSTID, HOSTIDTYPE and ACTION via homonym environment variables.
 - Action is authorized on error code 0. Otherwise, authorization is considered denied.
 - Will receive empty string if any of the values is not known (for example, if no host-id-type is provided)
 
## Update of signal file
On receiving `SIGHUP` signal, the server will finish the request that are being handled at that moment. After that, it will reload the same files that was originally provided, and update its information to its current state. Namely:
- Reload the key file and actualize its internal state according to it.  On receiving it the process DropAllReplace its key Manager with the keys that are in the given file.
- Reload the authorization script and update its internal state according to it.

## Dependencies
- [Cobra](https://github.com/spf13/cobra)
- [Go-yaml](https://github.com/go-yaml/yaml)
