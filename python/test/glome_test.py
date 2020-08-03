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
Module that implements unittests cases for Glome Module.
"""

import unittest
from cryptography.hazmat.primitives.asymmetric import x25519

import pyglome


class TestVector:
    """Class that encapsulate needed components for testing."""

    def __init__(self, kap, ka, kbp, kb, counter, msg, sk, tag,
                 truncated_length):
        self.kap = bytes.fromhex(kap)
        self.ka = bytes.fromhex(ka)
        self.kbp = bytes.fromhex(kbp)
        self.kb = bytes.fromhex(kb)
        self.counter = counter
        self.msg = msg
        self.sk = bytes.fromhex(sk)
        self.tag = bytes.fromhex(tag)


class GlomeTestVector(TestVector):
    """Class that encapsulates needed components for testing Glome Class."""

    def __init__(self, kap, ka, kbp, kb, counter, msg, sk, tag,
                 truncated_length):
        super(__class__, self).__init__(kap, ka, kbp, kb, counter, msg, sk, tag,
                                        truncated_length)

        peer_key = x25519.X25519PublicKey.from_public_bytes(self.kb)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.kap)
        self.sender_glomes = pyglome.Glome(peer_key, my_key)

        peer_key = x25519.X25519PublicKey.from_public_bytes(self.ka)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.kbp)
        self.receiver_glomes = pyglome.Glome(peer_key, my_key)

        self.truncated_tag_length = truncated_length

        peer_key = x25519.X25519PublicKey.from_public_bytes(self.kb)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.kap)
        self.truncated_sender_glomes = pyglome.Glome(peer_key, my_key,
                                                     self.truncated_tag_length)
        peer_key = x25519.X25519PublicKey.from_public_bytes(self.ka)
        my_key = x25519.X25519PrivateKey.from_private_bytes(self.kbp)
        self.truncated_receiver_glomes = pyglome.Glome(
            peer_key, my_key, self.truncated_tag_length)


class GlomeTestBase:
    """
    Test Class for Glome Class.

    Implements the logic for tests tag and key generation, as well as tag
    checking.
    """

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.test_vector = None

    def test_keys_generation(self):
        test_vector = self.test_vector
        self.assertEqual(test_vector.sender_glomes._send_key,
                         test_vector.sk + test_vector.kb + test_vector.ka)
        self.assertEqual(test_vector.sender_glomes._receive_key,
                         test_vector.sk + test_vector.ka + test_vector.kb)
        self.assertEqual(test_vector.receiver_glomes._send_key,
                         test_vector.sk + test_vector.ka + test_vector.kb)
        self.assertEqual(test_vector.receiver_glomes._receive_key,
                         test_vector.sk + test_vector.kb + test_vector.ka)

    def test_tag_generation(self):
        test_vector = self.test_vector
        self.assertEqual(
            test_vector.sender_glomes.tag(test_vector.msg, test_vector.counter),
            test_vector.tag)

    def test_check_raises_exception_when_incorrect(self):
        test_vector = self.test_vector
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.sender_glomes.check(tag=bytes([123]),
                                            msg=test_vector.msg,
                                            counter=0)
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.receiver_glomes.check(tag=bytes([234]),
                                              msg=test_vector.msg,
                                              counter=0)
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.sender_glomes.check(
                tag=test_vector.tag[:test_vector.truncated_tag_length],
                msg=test_vector.msg,
                counter=0)
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.truncated_receiver_glomes.check(
                tag=test_vector.tag[:test_vector.truncated_tag_length] +
                test_vector.tag[:test_vector.truncated_tag_length],
                msg=test_vector.msg,
                counter=test_vector.counter)
        with self.assertRaises(pyglome.IncorrectTagError):
            test_vector.truncated_receiver_glomes.check(
                tag=test_vector.tag[:test_vector.truncated_tag_length] +
                test_vector.tag[test_vector.truncated_tag_length::-1],
                msg=test_vector.msg,
                counter=test_vector.counter)

    def test_check_doesnt_raise_exception_when_correct(self):
        test_vector = self.test_vector
        try:
            test_vector.receiver_glomes.check(test_vector.tag,
                                              msg=test_vector.msg,
                                              counter=test_vector.counter)
            test_vector.truncated_receiver_glomes.check(
                test_vector.tag[:test_vector.truncated_tag_length],
                msg=test_vector.msg,
                counter=test_vector.counter)
            test_vector.truncated_receiver_glomes.check(
                test_vector.tag[:test_vector.truncated_tag_length + 2],
                msg=test_vector.msg,
                counter=test_vector.counter)
        except pyglome.IncorrectTagError:
            self.fail('check() raised IncorrectTagError unexpectedly!')


class Test1(unittest.TestCase, GlomeTestBase):
    """Test Vector #1 from the protocol reference"""

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.test_vector = GlomeTestVector(
            kap=
            '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
            ka=
            '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
            kbp=
            '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
            kb=
            'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
            counter=0,
            msg='The quick brown fox'.encode(),
            sk=
            '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
            tag=
            '9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3',
            truncated_length=8)


class Test2(unittest.TestCase, GlomeTestBase):
    """Test Vector #2 from the protocol reference"""

    def __init__(self, *args, **kwargs):
        super(__class__, self).__init__(*args, **kwargs)
        self.test_vector = GlomeTestVector(
            kap=
            'b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d',
            ka=
            'd1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647',
            kbp=
            'fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead',
            kb=
            '872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376',
            counter=100,
            msg='The quick brown fox'.encode(),
            sk=
            '4b1ee05fcd2ae53ebe4c9ec94915cb057109389a2aa415f26986bddebf379d67',
            tag=
            '06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277',
            truncated_length=8)


if __name__ == '__main__':
    unittest.main()
