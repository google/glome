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
This module includes test vectors from the protocol reference.
"""


class TestVector:
    """Class that encapsulate needed components for testing.

    Consider a use case where an user A sends a message to user B.

    Attributes:
      kap: A's private key.
      ka: A's public key.
      kbp: B's private key.
      kb:  B's public key.
      counter: number of messages already shared.
      msg: message to share.
      sk: shared secret betweens A and B.
      tag: tag that matches ka, kb, counter and msg.
    """

    def __init__(self, kap: str, ka: str, kbp: str, kb: str, counter: int,
                 msg: str, sk: str, tag: str):
        """Constructor for TestVector Class."""
        self.kap = bytes.fromhex(kap)
        self.ka = bytes.fromhex(ka)
        self.kbp = bytes.fromhex(kbp)
        self.kb = bytes.fromhex(kb)
        self.counter = counter
        self.msg = msg.encode(encoding="ascii")
        self.sk = bytes.fromhex(sk)
        self.tag = bytes.fromhex(tag)


TEST1 = TestVector(
    kap='77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    ka='8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    kbp='5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
    kb='de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
    counter=0,
    msg='The quick brown fox',
    sk='4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
    tag='9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3')

TEST2 = TestVector(
    kap='b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d',
    ka='d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647',
    kbp='fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead',
    kb='872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376',
    counter=100,
    msg='The quick brown fox',
    sk='4b1ee05fcd2ae53ebe4c9ec94915cb057109389a2aa415f26986bddebf379d67',
    tag='06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277')
