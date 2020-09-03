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
Module that implements unittests cases for AutoGlome Class.
"""
import unittest
from test import test_vectors
from cryptography.hazmat.primitives.asymmetric import x25519

import pyglome


class AutoGlomeTestVector:
    """Class that encapsulate needed components for testing AutoGlome Class."""

    def __init__(self, test_vector, min_peer_tag_len, skippable_range):
        self.data = test_vector
        self.skippable_range = skippable_range

        peer_key = x25519.X25519PublicKey.from_public_bytes(self.data.kb)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.data.kap)
        self.sender_glome = pyglome.AutoGlome(peer_key,
                                              my_key,
                                              min_peer_tag_len=min_peer_tag_len,
                                              skippable_range=skippable_range)

        peer_key = x25519.X25519PublicKey.from_public_bytes(self.data.ka)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.data.kbp)
        self.receiver_glome = pyglome.AutoGlome(
            peer_key,
            my_key,
            min_peer_tag_len=min_peer_tag_len,
            skippable_range=skippable_range)


class AutoGlomeTestBase:
    """Test keys constructions, tag generation and tag checking for AutoGlome."""

    def __init__(self):
        self.test_vector = None

    def test_check_counters_raise_exceptions_when_incorrect(self):
        test_vector = self.test_vector
        with self.assertRaises(ValueError):
            test_vector.sender_glome.sending_counter = -1
        with self.assertRaises(ValueError):
            test_vector.receiver_glome.sending_counter = 256
        with self.assertRaises(ValueError):
            test_vector.sender_glome.receiving_counter = 280
        with self.assertRaises(ValueError):
            test_vector.receiver_glome.receiving_counter = 280

    def test_check_counters_dont_raise_exceptions_when_correct(self):
        test_vector = self.test_vector
        try:
            test_vector.sender_glome.sending_counter = 0
            test_vector.receiver_glome.sending_counter = 23
            test_vector.sender_glome.receiving_counter = 123
            test_vector.receiver_glome.receiving_counter = 255
        except ValueError:
            self.fail('properties raised ValueError unexpectedly!')

    def test_check_counters_are_correctly_set(self):
        test_vector = self.test_vector
        test_vector.sender_glome.sending_counter = 0
        self.assertEqual(test_vector.sender_glome.sending_counter, 0)
        test_vector.receiver_glome.sending_counter = 23
        self.assertEqual(test_vector.receiver_glome.sending_counter, 23)
        test_vector.sender_glome.receiving_counter = 123
        self.assertEqual(test_vector.sender_glome.receiving_counter, 123)
        test_vector.receiver_glome.receiving_counter = 255
        self.assertEqual(test_vector.receiver_glome.receiving_counter, 255)

    def test_tag(self):
        test_vector = self.test_vector
        test_vector.sender_glome.sending_counter = test_vector.data.counter
        self.assertEqual(test_vector.sender_glome.tag(test_vector.data.msg),
                         test_vector.data.tag)

    def test_skippable_range(self):
        test_vector = self.test_vector
        try:
            test_vector.receiver_glome.receiving_counter = (
                test_vector.data.counter - test_vector.skippable_range) % 256
            test_vector.receiver_glome.check(test_vector.data.tag,
                                             msg=test_vector.data.msg)
            self.assertEqual((test_vector.data.counter + 1) % 256,
                             test_vector.receiver_glome.receiving_counter)
        except pyglome.IncorrectTagError:
            self.fail('check() raised IncorrectTagError unexpectedly!')


class AutoGlomeTest1(unittest.TestCase, AutoGlomeTestBase):
    """Autoglome test using test vector #1 from the protocol documentation."""

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.test_vector = AutoGlomeTestVector(test_vectors.TEST1,
                                               min_peer_tag_len=32,
                                               skippable_range=0)


class AutoTest2(unittest.TestCase, AutoGlomeTestBase):
    """Autoglome test using test vector #2 from the protocol documentation."""

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.test_vector = AutoGlomeTestVector(test_vectors.TEST2,
                                               min_peer_tag_len=8,
                                               skippable_range=10)


if __name__ == '__main__':
    unittest.main()
