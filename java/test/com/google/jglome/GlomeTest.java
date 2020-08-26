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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.jglome.Glome.CounterOutOfBoundsException;
import com.google.jglome.Glome.GlomeBuilder;
import com.google.jglome.Glome.MinPeerTagLengthOutOfBoundsException;
import com.google.jglome.Glome.WrongTagException;
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

  GlomeTest() {
    for (int tv = 0; tv < N_TEST_VECTORS; tv++) {
      TestVector testVector = TEST_VECTORS.get(tv);
      aKeys[tv] = new KeyPair(testVector.getKa(), testVector.getKah());
      bKeys[tv] = new KeyPair(testVector.getKb(), testVector.getKbh());
      int finalTV = tv;
      glomeManagers[tv][0] = assertDoesNotThrow(() ->
          new GlomeBuilder(bKeys[finalTV].getPublicKey(), 32)
              .setPrivateKey(aKeys[finalTV].getPrivateKey())
              .build()
      );
      glomeManagers[tv][1] = assertDoesNotThrow(() ->
          new GlomeBuilder(aKeys[finalTV].getPublicKey(), 28)
              .setPrivateKey(bKeys[finalTV].getPrivateKey())
              .build()
      );
    }
  }

  @Test
  public void testShouldFail_whenMinPeerTagLengthIsOutOfBounds() {
    int[] minPeerTagLength = new int[]{MIN_TAG_LENGTH - 1, MAX_TAG_LENGTH + 1};

    for (int len : minPeerTagLength) {
      MinPeerTagLengthOutOfBoundsException e = assertThrows(
          MinPeerTagLengthOutOfBoundsException.class,
          () -> new GlomeBuilder(aKeys[0].getPublicKey(), len)
      );
      assertEquals(
          e.getMessage(),
          String.format(
              "minPeerTagLength argument should be in [%d..%d] range. Got %d.",
              MIN_TAG_LENGTH, MAX_TAG_LENGTH, len
          )
      );
    }
  }

  @Test
  public void checkCorrectMinPeerTagLength() {
    for (int tagLen = MIN_TAG_LENGTH; tagLen <= MAX_TAG_LENGTH; tagLen++) {
      int finalTagLen = tagLen;
      assertDoesNotThrow(() -> new GlomeBuilder(aKeys[0].getPublicKey(), finalTagLen));
    }
  }

  @Test
  public void testShouldFail_whenCounterIsOutOfBounds() {
    TestVector vector = TEST_VECTORS.get(0);
    int[] counters = new int[]{MIN_CNT_VALUE - 1, MAX_CNT_VALUE + 1};

    for (int cnt : counters) {
      CounterOutOfBoundsException e = assertThrows(
          CounterOutOfBoundsException.class,
          () -> glomeManagers[0][0].generateTag(vector.getMsg(), cnt)
      );
      assertEquals(
          e.getMessage(),
          String.format(
              "Counter should be in [%d..%d] range. Got %d.",
              MIN_CNT_VALUE, MAX_CNT_VALUE, cnt
          )
      );
    }
  }

  @Test
  public void checkCorrectCounters() {
    TestVector vector = TEST_VECTORS.get(0);

    for (int cnt = MIN_CNT_VALUE; cnt < MAX_CNT_VALUE; cnt++) {
      int finalCnt = cnt;
      assertDoesNotThrow(() -> glomeManagers[0][0].generateTag(vector.getMsg(), finalCnt));
    }
  }

  @Test
  public void derivedKeyShouldEqualOriginalKey() {
    for (int tv = 0; tv < N_TEST_VECTORS; tv++) {
      assertArrayEquals(aKeys[tv].getPublicKey(), glomeManagers[tv][0].userPublicKey());
      assertArrayEquals(bKeys[tv].getPublicKey(), glomeManagers[tv][1].userPublicKey());
    }
  }

  @Test
  public void testTagGeneration() {
    for (int tv = 0; tv < N_TEST_VECTORS; tv++) {
      TestVector vector = TEST_VECTORS.get(tv);
      int sender = tv % 2;
      int finalTV = tv;
      assertArrayEquals(
          vector.getTag(),
          assertDoesNotThrow(() ->
              glomeManagers[finalTV][sender].generateTag(vector.getMsg(), vector.getCnt())
          )
      );
    }
  }

  @Test
  public void testCheckTag() {
    for (int tv = 0; tv < N_TEST_VECTORS; tv++) {
      TestVector vector = TEST_VECTORS.get(tv);
      int receiver = 1 - tv % 2;
      int finalTV = tv;
      assertDoesNotThrow(() ->
          glomeManagers[finalTV][receiver]
              .checkTag(vector.getTag(), vector.getMsg(), vector.getCnt())
      );
    }
  }

  @Test
  public void testCorrectTruncatedTag() {
    TestVector vector = TEST_VECTORS.get(0);
    assertDoesNotThrow(() ->
        glomeManagers[0][1]
            .checkTag(Arrays.copyOf(vector.getTag(), 29), vector.getMsg(), vector.getCnt())
    );
  }

  @Test
  public void testShouldFail_whenIncorrectTruncatedTag() {
    TestVector vector = TEST_VECTORS.get(0);
    byte[] truncatedTag = Arrays.copyOf(vector.getTag(), 29);
    truncatedTag[28] = 0;

    WrongTagException e = assertThrows(
        WrongTagException.class,
        () -> glomeManagers[0][1].checkTag(truncatedTag, vector.getMsg(), vector.getCnt())
    );

    assertEquals("The received tag doesn't match the expected tag.", e.getMessage());
  }

  @Test
  public void testShouldFail_whenInvalidTagLen() {
    TestVector vector = TEST_VECTORS.get(0);
    byte[] truncatedTag = Arrays.copyOf(vector.getTag(), 27);

    WrongTagException e = assertThrows(
        WrongTagException.class,
        () -> glomeManagers[0][1].checkTag(truncatedTag, vector.getMsg(), vector.getCnt())
    );

    assertEquals(
        String.format(
            "The received tag has invalid length. Expected value in range [%d..%d], got %d.",
            28, MAX_TAG_LENGTH, truncatedTag.length),
        e.getMessage()
    );
  }

}
