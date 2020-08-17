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
"""Python GLOME library.

This module contains the Glome class and generate_keys function.

Example use: Sender

>>> import pyglome
>>> tag_manager = pyglome.Glome(peer_key)
>>> first_tag = tag_manager.tag(first_msg, 0) # 0 as it is the first msg
>>> second_tag = tag_manager.tag(second_msg, 1)

Example use: Receiver

>>> import pyglome
>>> tag_manager = pyglome.Glome(peer_key, my_private_key)
>>> ## Need to have a private key (paired to the public key
>>> ## that the sender use)
>>> try:
...     tag_manager.check(tag, msg, counter=0):
>>> except pyglome.IncorrectTagError as wte:
...     ## Handle the exception
>>> ## do what you have to do
"""

import os
import hashlib
import hmac
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


class KeyPair(NamedTuple):
    """
    NamedTuple-Class that stores a private/public key pair.

    Attributes:
        - private: A private key.
        - public: A public key paired with the private one.
    """
    private: x25519.X25519PrivateKey
    public: x25519.X25519PublicKey


class Error(Exception):
    """Error super-class for any error that is thrown in PyGLOME."""


class TagCheckError(Error):
    """Raised whenever a tag is not correct or the method failed to check it."""


class IncorrectTagError(Error):
    """Raised whenever the tag provided does not match the message and counter."""


class TagGenerationError(Error):
    """Raised whenever a tag could not be generated."""


def _public_key_encode(public_key: x25519.X25519PublicKey):
    return public_key.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)


def _tag(msg: bytes, counter: int, key: bytes) -> bytes:
    if counter < 0 or counter > 255:
        raise ValueError(
            'Counters for tags must be in range 0-255, not {}'.format(counter))

    message = bytes([counter]) + msg  # msg: N_x|M_n
    digester = hmac.new(key=key, msg=message, digestmod=hashlib.sha256)
    return digester.digest()


class Glome:
    """Implement tag managing functionalities for GLOME protocol.

    This class is initialized by providing your peer's public key and
    optionally your private key. If a private key is not provided, one is
    automatically generated making use of `generate_keys`. Provides methods
    tag (to generate new tags) and check (to check receiving tags).
    """

    MAX_TAG_LEN = 32  # 32 is maximum tag length
    MIN_TAG_LEN = 1

    def __init__(self,
                 peer_key: x25519.X25519PublicKey,
                 my_private_key: x25519.X25519PrivateKey = None,
                 min_peer_tag_len: int = MAX_TAG_LEN):
        """Initialize Glome class.

        Performs the handshake and generates keys. 

        Args:
            peer_key: Your peer's public key.
            my_private_key: Your private key.
            min_peer_tag_len: Desired length (in bytes) for the tag.
              Must be an integer in range 1-32.
        Raises:
            ValueError: Raised whenever min_peer_tag_len is not in
              range 1-32.
        """

        if my_private_key is None:
            my_private_key, my_public_key = generate_keys()
        else:
            my_public_key = my_private_key.public_key()

        if not Glome.MIN_TAG_LEN < min_peer_tag_len <= Glome.MAX_TAG_LEN:
            raise ValueError('min_peer_tag_len must be in range {}-{}'.format(
                Glome.MIN_TAG_LEN, Glome.MAX_TAG_LEN))

        shared_secret = my_private_key.exchange(peer_key)

        self._send_key = shared_secret + _public_key_encode(
            peer_key) + _public_key_encode(my_public_key)
        self._receive_key = shared_secret + _public_key_encode(
            my_public_key) + _public_key_encode(peer_key)
        self._peer_key = peer_key
        self._my_keys = KeyPair(my_private_key, my_public_key)
        self._min_peer_tag_len = min_peer_tag_len

    @property
    def user_keys(self) -> KeyPair:
        """User's private and public keys used in handshake."""
        return self._my_keys

    @property
    def peer_key(self) -> x25519.X25519PublicKey:
        """Peer's public key used in handshake."""
        return self._peer_key

    def tag(self, msg: bytes, counter: int) -> bytes:
        """Generates a tag from a message and a counter.

        Generates a tag matching some provided message and counter.
        This tag is generated following GLOME protocol specification
        in the context of a communication from the users to theirs peers.

        Args:
           msg: Message to be transmitted.
           counter: Numbers of messages transmitted previously in the
             conversation in this direction (i.e. from the user
             to the peer). Must be an integer in {0,...,255}.
        Returns:
           tag: Tag matching counter and msg.
        Raises:
           TagGenerationError: Raised whenever the method failed to generate tag
             due to ValueError in the arguments.
        """
        try:
            return _tag(msg, counter, self._send_key)
        except ValueError as value_error:
            raise TagGenerationError('Failed to generate tag') from value_error

    def check(self, tag: bytes, msg: bytes, counter: int):
        """Check whether a tag is correct for some message and counter.

        Checks if a tag matches some provided message and counter.
        The method generates the matching tag following GLOME protocol
        specification in the context of a communication from the users'
        peers to the users and then is compared with the tag provided.

        Args:
           tag: Object with the generated tag.
           msg: Object containing received message.
           counter: Numbers of messages transmitted previously in the
             conversation in this direction (i.e. from the peer
             to the user).
        Returns:
           None.
        Raises:
           TagCheckError: Raised whenever the method fails to check the tag
             due to a ValueError in the arguments.
           IncorrectTagError: Raised whenever the tag is incorrect.
        """
        prefix_length = max(len(tag), self._min_peer_tag_len)
        prefix_length = min(prefix_length, Glome.MAX_TAG_LEN)

        try:
            correct_tag = _tag(msg, counter, self._receive_key)[:prefix_length]
        except ValueError as value_error:
            raise TagCheckError('Failed to check the tag') from value_error

        if not hmac.compare_digest(tag, correct_tag):
            raise IncorrectTagError('Tag provided does not match correct tag')


def generate_keys() -> KeyPair:
    """Generates a private/public key pair.

    Provides a random key pair based output of os.urandom. The format
    matches the one requested by Glome Class.

    Args:
       None
    Returns:
       A KeyPair, containing a random private key and the public key derived
       from the generated private key
    """
    private = x25519.X25519PrivateKey.from_private_bytes(
        os.urandom(Glome.MAX_TAG_LEN))
    return KeyPair(private, private.public_key())
