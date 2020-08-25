// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.jglome;

import static com.google.jglome.Glome.MAX_CNT_VALUE;
import static com.google.jglome.Glome.MAX_TAG_LENGTH;
import static com.google.jglome.Glome.MIN_CNT_VALUE;
import static com.google.jglome.Glome.MIN_TAG_LENGTH;
import static com.google.jglome.TestVector.TEST_VECTORS;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.jglome.Glome.CounterOutOfBoundsException;
import com.google.jglome.Glome.GlomeBuilder;
import com.google.jglome.Glome.MinPeerTagLengthOutOfBoundsException;
import com.google.jglome.Glome.WrongTagException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Contains tests for com.google.jglome.Glome functionality.
 */
public class GlomeTest {

  public static class KeyPair {

    private byte[] publicKey;
    private byte[] privateKey;

    KeyPair(byte[] publicKey, byte[] privateKey) {
      this.publicKey = publicKey;
      this.privateKey = privateKey;
    }

    public byte[] getPrivateKey() {
      return privateKey;
    }

    public byte[] getPublicKey() {
      return publicKey;
    }
  }

  final static int N_TEST_VECTORS = TEST_VECTORS.size();

  Glome[][] glomeManagers = new Glome[N_TEST_VECTORS][2]; // first is for A, second is for B
  KeyPair[] aKeys = new KeyPair[N_TEST_VECTORS];
  KeyPair[] bKeys = new KeyPair[N_TEST_VECTORS];

  GlomeTest() throws MinPeerTagLengthOutOfBoundsException, InvalidKeyException {
    for (int i = 0; i < N_TEST_VECTORS; i++) {
      TestVector testVector = TEST_VECTORS.get(i);
      aKeys[i] = new KeyPair(testVector.getKa(), testVector.getKah());
      bKeys[i] = new KeyPair(testVector.getKb(), testVector.getKbh());
      glomeManagers[i][0] = new GlomeBuilder(bKeys[i].getPublicKey(), 32)
          .setPrivateKey(aKeys[i].getPrivateKey())
          .build();
      glomeManagers[i][1] = new GlomeBuilder(aKeys[i].getPublicKey(), 28)
          .setPrivateKey(bKeys[i].getPrivateKey())
          .build();
    }
  }

  @Test
  public void testShouldFailWhenMinPeerTagLengthIsOutOfBounds() {
    int[] minPeerTagLength = new int[]{MIN_TAG_LENGTH - 1, MAX_TAG_LENGTH + 1};

    for (int len : minPeerTagLength) {
      try {
        new GlomeBuilder(aKeys[0].getPublicKey(), len);
      } catch (MinPeerTagLengthOutOfBoundsException e) {
        assertEquals(e.getMessage(),
            String.format("minPeerTagLength argument should be in [%d..%d] range. Got %d.",
                MIN_TAG_LENGTH, MAX_TAG_LENGTH, len));
      }
    }
  }

  @Test
  public void checkCorrectMinPeerTagLength() {
    for (int len = MIN_TAG_LENGTH; len <= MAX_TAG_LENGTH; len++) {
      try {
        new GlomeBuilder(aKeys[0].getPublicKey(), len);
      } catch (MinPeerTagLengthOutOfBoundsException e) {
        assertEquals(e.getMessage(),
            String.format("minPeerTagLength argument should be in [%d..%d] range. Got %d.",
                MIN_TAG_LENGTH, MAX_TAG_LENGTH, len));
      }
    }
  }

  @Test
  public void testShouldFailWhenCounterIsOutOfBounds() {
    TestVector vector = TEST_VECTORS.get(0);
    int[] counters = new int[]{MIN_CNT_VALUE - 1, MAX_CNT_VALUE + 1};

    for (int cnt : counters) {
      try {
        glomeManagers[0][0].generateTag(vector.getMsg(), cnt);
      } catch (CounterOutOfBoundsException e) {
        assertEquals(e.getMessage(),
            String.format("Counter should be in [%d..%d] range. Got %d.", MIN_CNT_VALUE,
                MAX_CNT_VALUE, cnt));
      }
    }
  }

  @Test
  public void checkCorrectCounters() throws CounterOutOfBoundsException {
    TestVector vector = TEST_VECTORS.get(0);

    for (int cnt = MIN_CNT_VALUE; cnt < MAX_CNT_VALUE; cnt++) {
      glomeManagers[0][0].generateTag(vector.getMsg(), cnt);
    }
  }

  @Test
  public void derivedKeyShouldEqualOriginalKey() {
    for (int i = 0; i < N_TEST_VECTORS; i++) {
      assertArrayEquals(aKeys[i].getPublicKey(), glomeManagers[i][0].userPublicKey());
      assertArrayEquals(bKeys[i].getPublicKey(), glomeManagers[i][1].userPublicKey());
    }
  }

  @Test
  public void testTagGeneration() throws CounterOutOfBoundsException {
    for (int i = 0; i < N_TEST_VECTORS; i++) {
      TestVector vector = TEST_VECTORS.get(i);
      int sender = i % 2;
      assertArrayEquals(vector.getTag(),
          glomeManagers[i][sender].generateTag(vector.getMsg(), vector.getCnt()));
    }
  }

  @Test
  public void testCheckTag() throws WrongTagException, CounterOutOfBoundsException {
    for (int i = 0; i < N_TEST_VECTORS; i++) {
      TestVector vector = TEST_VECTORS.get(i);
      int receiver = 1 - i % 2;
      glomeManagers[i][receiver].checkTag(vector.getTag(), vector.getMsg(), vector.getCnt());
    }
  }

  @Test
  public void testCorrectTruncatedTag() throws WrongTagException, CounterOutOfBoundsException {
    TestVector vector = TEST_VECTORS.get(0);
    glomeManagers[0][1]
        .checkTag(Arrays.copyOf(vector.getTag(), 29), vector.getMsg(), vector.getCnt());
  }

  @Test
  public void testShouldFailWhenIncorrectTruncatedTag() throws CounterOutOfBoundsException {
    TestVector vector = TEST_VECTORS.get(0);
    byte[] truncatedTag = Arrays.copyOf(vector.getTag(), 29);
    truncatedTag[28] = 0;

    try {
      glomeManagers[0][1].checkTag(truncatedTag, vector.getMsg(), vector.getCnt());
    } catch (WrongTagException e) {
      assertEquals("The received tag doesn't match the expected tag.", e.getMessage());
    }
  }

}
