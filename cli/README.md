# GLOME CLI

This is a CLI utility to facilitate GLOME operations from the command line.

## Usage

Generating two key pairs:

```shell
glome genkey | tee Alice | glome pubkey >Alice.pub
glome genkey | tee Bob   | glome pubkey >Bob.pub
```

Alice calculates a tag and send it together with message and counter to Bob:

```shell
$ tag=$(echo "Hello world!" | glome tag --key Alice --peer Bob.pub)

$ echo "${tag?}"
_QuyLz_nkj5exUJscocS8LDnCMszvSmp9wpQuRshi30=
```

Bob can verify that the tag matches:

```shell
$ echo "Hello world!" | glome verify --key Bob --peer Alice.pub --tag "${tag?}"

$ echo $?
0
```

Both parties can agree to shorten the tag to reduce the protocol overhead:

```shell
$ echo "Hello world!" | glome verify --key Bob --peer Alice.pub --tag "${tag:0:12}"

$ echo $?
0
```

CLI also supports ganerating tags for the GLOME Login requests:

```shell
$ glome login --key Bob https://glome.example.com/v1/AYUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q0PU=/my-server.local/shell/root/
MT_Zc-hucXRjTXTBEo53ehoeUsFn1oFyVadViXf-I4k=
```
