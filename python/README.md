# PyGLOME
**This is not an officially supported Google product.**

This repository contains a Python implementation for the GLOME
protocol. You can find the library in the folder pyglome. The test
files can be found in the test folder.

## Python API

### Requirements

-   Python >= 3.6
-   pyca/cryptography >= 2.5

### Example

We provide a brief example of use.  In order for Alice and Bob to communicate,
the first step would be to generate some new keys:

```python
import pyglome

alice_keys = pyglome.generate_keys()
bob_keys = pyglome.generate_keys()
```

Suppose that Alice knows Bob's `public_key` and wants to send Bob the message
`msg` and no other message have been shared before. Alice will need to:

```python
glome = pyglome.Glome(bob_keys.public, alice_keys.private)
first_tag = glome.tag(msg, counter=0)
```

And Alice will send Bob both `msg`, `first_tag` as well as Alice's public key.
On Bob's end he will need to do the following:

```python
glome = pyglome.Glome(alice_keys.public, bob_keys.private)
try:
    glome.check(first_tag, msg, counter=0)
except pyglome.TagCheckError as tag_error:
    ## Handle the exception.
## do what you have to do
```

### Key generation.

Should you want to use a preexisting key, it should match the format
`X25519Private/PublicKey` provided in [pyca/cryptography](https://cryptography.io/en/latest/).
Such a key can be easily read from a bytes object as follows:

```python
from cryptography.hazmat.primitives.asymmetric import x25519
my_private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
my_public_key = x25519.X25519PublicKey.from_private_bytes(public_key_bytes)
```

We provide a key generation function `generate_keys` that uses these methods to
create a new key pair from `os.urandom` bytes.

### Documentation

For more information see the in-code documentation.

### Test

In the test folder we have scripts that implement test classes based on unittest. To run all tests use:

```
python -m test
```
from this directory. If you only want to execute a particular test module, then run:

```
python -m test.my_module_name
```

where `my_module_name` is the name of the test module to be executed (the name of the file without the .py).
