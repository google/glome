#!/usr/bin/env python3
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
Module that implements unittests cases for Glome Class.
"""

import unittest
from cryptography.hazmat.primitives.asymmetric import x25519

import pyglome
from test import test_vectors


class GlomeTestVector:
    """Class that encapsulates needed components for testing Glome Class."""

    def __init__(self, test_vector, truncated_length):
        self.data = test_vector

        peer_key = x25519.X25519PublicKey.from_public_bytes(self.data.kb)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.data.kap)
        self.sender_glomes = pyglome.Glome(peer_key, my_key)

        peer_key = x25519.X25519PublicKey.from_public_bytes(self.data.ka)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.data.kbp)
        self.receiver_glomes = pyglome.Glome(peer_key, my_key)

        self.truncated_tag_length = truncated_length

        peer_key = x25519.X25519PublicKey.from_public_bytes(self.data.kb)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.data.kap)
        self.truncated_sender_glomes = pyglome.Glome(peer_key, my_key,
                                                     self.truncated_tag_length)
        peer_key = x25519.X25519PublicKey.from_public_bytes(self.data.ka)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.data.kbp)
        self.truncated_receiver_glomes = pyglome.Glome(
            peer_key, my_key, self.truncated_tag_length)


class GlomeTestBase:
    """Test Class for Glome Class.

    Implements the logic for tests tag and key generation, as well as tag
    checking.
    """

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.test_vector = None

    def test_keys_generation(self):
        test_vector = self.test_vector
        self.assertEqual(
            test_vector.sender_glomes._send_key,
            test_vector.data.sk + test_vector.data.kb + test_vector.data.ka)
        self.assertEqual(
            test_vector.sender_glomes._receive_key,
            test_vector.data.sk + test_vector.data.ka + test_vector.data.kb)
        self.assertEqual(
            test_vector.receiver_glomes._send_key,
            test_vector.data.sk + test_vector.data.ka + test_vector.data.kb)
        self.assertEqual(
            test_vector.receiver_glomes._receive_key,
            test_vector.data.sk + test_vector.data.kb + test_vector.data.ka)

    def test_tag_generation(self):
        test_vector = self.test_vector
        self.assertEqual(
            test_vector.sender_glomes.tag(test_vector.data.msg,
                                          test_vector.data.counter),
            test_vector.data.tag)

    def test_check_raises_exception_when_incorrect(self):
        test_vector = self.test_vector
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.sender_glomes.check(tag=bytes([123]),
                                            msg=test_vector.data.msg,
                                            counter=0)
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.receiver_glomes.check(tag=bytes([234]),
                                              msg=test_vector.data.msg,
                                              counter=0)
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.sender_glomes.check(
                tag=test_vector.data.tag[:test_vector.truncated_tag_length],
                msg=test_vector.data.msg,
                counter=0)
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.truncated_receiver_glomes.check(
                tag=test_vector.data.tag[:test_vector.truncated_tag_length] +
                test_vector.data.tag[:test_vector.truncated_tag_length],
                msg=test_vector.data.msg,
                counter=test_vector.data.counter)
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.truncated_receiver_glomes.check(
                tag=test_vector.data.tag[:test_vector.truncated_tag_length] +
                test_vector.data.tag[test_vector.truncated_tag_length::-1],
                msg=test_vector.data.msg,
                counter=test_vector.data.counter)

    def test_check_doesnt_raise_exception_when_correct(self):
        test_vector = self.test_vector
        try:
            test_vector.receiver_glomes.check(test_vector.data.tag,
                                              msg=test_vector.data.msg,
                                              counter=test_vector.data.counter)
            test_vector.truncated_receiver_glomes.check(
                test_vector.data.tag[:test_vector.truncated_tag_length],
                msg=test_vector.data.msg,
                counter=test_vector.data.counter)
            test_vector.truncated_receiver_glomes.check(
                test_vector.data.tag[:test_vector.truncated_tag_length + 2],
                msg=test_vector.data.msg,
                counter=test_vector.data.counter)
        except pyglome.IncorrectTagError:
            self.fail('check() raised IncorrectTagError unexpectedly!')


class GlomeTest1(unittest.TestCase, GlomeTestBase):
    """TestCase based on test vector #1 from protocol documentation"""

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.test_vector = GlomeTestVector(test_vectors.TEST1, 8)


class GlomeTest2(unittest.TestCase, GlomeTestBase):
    """TestCase based on test vector #1 from protocol documentation"""

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.test_vector = GlomeTestVector(test_vectors.TEST2, 8)


if __name__ == '__main__':
    unittest.main()
