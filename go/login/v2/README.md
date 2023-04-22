# GLOME Login Golang API v2

This package implements version 2 of the GLOME Login challenge response
protocol, as described in the [specification](../../../docs/glome-login.md) and
[RFD001](../../../docs/rfd/001.md).

## Design

The API is designed with two groups of users in mind: clients and servers.
In the GLOME Login protocol, clients generate *challenges* which are
*responded to* by servers. This is reflected in the two basic structs defined
here, `v2.Challenger` and `v2.Responder`.

The other important struct is `v2.Message`, which contains all context for the
authorization decision. The genral flow is:

1. Client creates a `v2.Challenger` object including server configuration.
   This object is long-lived and can be reused.
2. An authorization decision needs to be made. The client phrases it in form of
   a `v2.Message` and produces an encoded challenge.
3. The challenge is transferred to the server, which holds a long-lived
   `v2.Responder` object that manages keys.
4. The server accepts the challenge, inspects the message and - if justified -
   authorizes by handing out the response code.
5. The response code is transferred to the client, which validates the code and
   grants access.

## Example

There's an example GLOME Login flow in [login_test.go](login_test.go).
