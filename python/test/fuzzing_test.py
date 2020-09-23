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
"""Python GLOME fuzz main.

This module that implement some easy fuzz testing for pyglome. 
"""

import hypothesis
import unittest
from cryptography.hazmat.primitives.asymmetric import x25519

import pyglome


def _glome(private_bytes, public_bytes, msg, tag, counter, min_tag_len):
    """Calls basic utilities of glome class, accepts only documented exceptions.

    The intention of this function is to be fuzzed over to find cases that throw
    unexpected exceptions."""
    try:
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        peer_key = x25519.X25519PublicKey.from_public_bytes(public_bytes)
    except (ValueError, pyglome.ExchangeError):
        return

    try:
        tag_manager = pyglome.Glome(peer_key, private_key, min_tag_len)
    except ValueError:
        return

    # Call to property method to test side effects
    tag_manager.user_keys
    tag_manager.peer_key

    try:
        tag_manager.tag(msg, counter)
    except pyglome.TagGenerationError:
        pass

    try:
        tag_manager.check(tag, msg, counter)
    except (pyglome.IncorrectTagError, pyglome.TagCheckError):
        pass


def _autoglome(private_bytes, public_bytes, msg, tag, counter, min_tag_len,
               skippable_range):
    """Calls basic utilities of autoglome class, accepts only documented exceptions.

    The intention of this function is to be fuzzed over to find cases that throw
    unexpected exceptions."""
    try:
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        peer_key = x25519.X25519PublicKey.from_public_bytes(public_bytes)
    except (ValueError, pyglome.ExchangeError):
        return

    try:
        tag_manager = pyglome.AutoGlome(peer_key,
                                        private_key,
                                        min_peer_tag_len=min_tag_len,
                                        skippable_range=skippable_range)
    except ValueError:
        return

    # Call to property method to test side effects
    tag_manager.user_keys
    tag_manager.peer_key
    tag_manager.sending_counter
    tag_manager.receiving_counter

    try:
        tag_manager.sending_counter = counter
    except ValueError:
        pass

    try:
        tag_manager.receiving_counter = counter
    except ValueError:
        pass

    try:
        tag_manager.tag(msg)
    except pyglome.TagGenerationError:
        pass

    try:
        tag_manager.check(tag, msg)
    except (pyglome.IncorrectTagError, pyglome.TagCheckError):
        pass


@hypothesis.settings(max_examples=10**7)
@hypothesis.given(
    hypothesis.strategies.binary(min_size=32, max_size=32),  #private_bytes
    hypothesis.strategies.binary(min_size=32, max_size=32),  #public_bytes
    hypothesis.strategies.binary(),  #msg
    hypothesis.strategies.binary(min_size=32, max_size=32),  #tag
    hypothesis.strategies.integers(),  #counter
    hypothesis.strategies.integers())  #min_tag_len
def glome_test(private_bytes, public_bytes, msg, tag, counter, min_tag_len):
    """Add hypothesis decorator to _glome function"""
    _glome(private_bytes, public_bytes, msg, tag, counter, min_tag_len)


@hypothesis.settings(max_examples=10**7)
@hypothesis.given(
    hypothesis.strategies.binary(min_size=32, max_size=32),  #private_bytes
    hypothesis.strategies.binary(min_size=32, max_size=32),  #public_bytes
    hypothesis.strategies.binary(),  #msg
    hypothesis.strategies.binary(min_size=32, max_size=32),  #tag
    hypothesis.strategies.integers(),  #counter
    hypothesis.strategies.integers(),  #min_tag_len
    hypothesis.strategies.integers())  #skippable
def autoglome_test(private_bytes, public_bytes, msg, tag, counter, min_tag_len,
                   skippable):
    """Add hypothesis decorator to _autoglome function"""
    _autoglome(private_bytes, public_bytes, msg, tag, counter, min_tag_len,
               skippable)


class GlomeTest1(unittest.TestCase):
    """Test Class that check one iteration of each function.

    Uses sample input to test whether the fuzzing function raise unexpected
    exceptions."""

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        constant_one = b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11'
        self.private_bytes = constant_one
        self.public_bytes = constant_one
        self.msg = b'\x11'
        self.tag = constant_one
        self.counter = 1
        self.min_tag_len = 1
        self.skippable = 1

    def test_glome_fuzz(self):
        """Test glome fuzzing function with trivial example"""
        try:
            _glome(self.private_bytes, self.public_bytes, self.msg, self.tag,
                   self.counter, self.min_tag_len)
        except:
            self.fail('Unexpected exception was raised.')

    def test_autoglome_fuzz(self):
        """Test autoglome fuzzing function with trivial example"""
        try:
            _autoglome(self.private_bytes, self.public_bytes, self.msg,
                       self.tag, self.counter, self.min_tag_len, self.skippable)
        except:
            self.fail('Unexpected exception was raised.')


if __name__ == "__main__":
    glome_test()
    autoglome_test()
