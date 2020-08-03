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
import sys

import test.glome_test, test.autoglome_test


def suite():
    """Suite of test to run"""
    glome_tests = unittest.TestLoader().loadTestsFromModule(test.glome_test)
    autoglome_tests = unittest.TestLoader().loadTestsFromModule(
        test.autoglome_test)

    return unittest.TestSuite([glome_tests, autoglome_tests])


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())  # Nice verbosy output

    result = unittest.TestResult()
    suite().run(result)
    sys.exit(len(result.errors) + len(result.failures))  # Correct exitcode
