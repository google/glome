# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
PyGLOME is a Python library that provides an API for GLOME protocol.

Basic Usage:
In order for Alice and Bob to communicate, the first step would be to generate
some new keys:

>>> import pyglome
>>> alice_keys = pyglome.generate_keys()
>>> bob_keys = pyglome.generate_keys()

Suppose that Alice knows Bob's `public_key` and wants to send Bob the message
`msg` and no other message have been shared before. Alice will need to:

>>> glome = pyglome.Glome(bob_keys.public, alice_keys.private)
>>> first_tag = glome.tag(msg, counter=0)

And Alice will send Bob both msg, first_tag as well as Alice's public key. On
Bob ends he will need to do the following:

>>> glome = pyglome.Glome(alice_keys.public, bob_keys.private)
>>> try:
...     first_tag = glome.check(first_tag, msg, counter=0)
... except pyglome.TagCheckError as tag_error:
...     ## Handle the exception.
>>> ## do what you have to do
"""

# Bring glome module to top level
from pyglome.glome import (Glome, TagCheckError, IncorrectTagError,
                           TagGenerationError, generate_keys, AutoGlome)
