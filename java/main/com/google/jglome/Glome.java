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

import static java.lang.System.arraycopy;

import com.google.crypto.tink.subtle.X25519;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encapsulates the logic of GLOME protocol.
 */
public final class Glome {

  private byte[] peerKey;
  private Mac userMacKey;
  private Mac peerMacKey;
  private int minPeerTagLength;

  private final byte[] userPublicKey;
  private final byte[] userPrivateKey;

  public static final int MIN_CNT_VALUE = 0;
  public static final int MAX_CNT_VALUE = 255;
  public static final int MAX_TAG_LENGTH = 32;
  public static final int MIN_TAG_LENGTH = 1;

  /**
   * Builder class for Glome object.
   */
  public static class GlomeBuilder {

    private final byte[] peerKey;
    private final int minPeerTagLength;
    private byte[] userPublicKey;
    private byte[] userPrivateKey;
    private Mac userMac;
    private Mac peerMac;

    {
      try {
        userMac = Mac.getInstance("HmacSHA256");
        peerMac = Mac.getInstance("HmacSHA256");
      } catch (NoSuchAlgorithmException e) {
        throw new AssertionError(e.getMessage());
      }
    }

    /**
     * Initializes peer's public key and minimum length for peer's tags.
     *
     * @param peerKey peer's public key.
     * @param minPeerTagLength minimum length for peer's tags.
     * @throws MinPeerTagLengthOutOfBoundsException if a minimum tag length is out of
     *     [MIN_TAG_LENGTH..MAX_TAG_LENGTH] range.
     */
    public GlomeBuilder(byte[] peerKey, int minPeerTagLength)
        throws MinPeerTagLengthOutOfBoundsException {
      if (minPeerTagLength < MIN_TAG_LENGTH || minPeerTagLength > MAX_TAG_LENGTH) {
        throw new MinPeerTagLengthOutOfBoundsException(
            String.format(
                "minPeerTagLength argument should be in [%d..%d] range. Got %d.",
                MIN_TAG_LENGTH, MAX_TAG_LENGTH, minPeerTagLength
            )
        );
      }
      this.minPeerTagLength = minPeerTagLength;
      this.peerKey = peerKey;
    }

    /**
     * Initializes user's private key.
     *
     * @param userPrivateKey user's private key.
     * @return current GlomeBuilder object.
     */
    public GlomeBuilder setPrivateKey(byte[] userPrivateKey) {
      this.userPrivateKey = userPrivateKey;
      return this;
    }

    /**
     * Initializes user's private key (if it hadn't been initialized before), user's public key and
     * each party's MAC key.
     */
    public Glome build() throws InvalidKeyException {
      if (userPrivateKey == null) {
        userPrivateKey = X25519.generatePrivateKey();
      }
      userPublicKey = X25519.publicFromPrivate(userPrivateKey);
      initMacKeys();

      return new Glome(this);
    }

    /**
     * Calculates user's and peer's MAC keys.
     *
     * @throws InvalidKeyException if any used key is invalid.
     */
    private void initMacKeys() throws InvalidKeyException {
      byte[] sharedSecret = X25519.computeSharedSecret(userPrivateKey, peerKey);
      initMacKey(userMac, sharedSecret, peerKey, userPublicKey);
      initMacKey(peerMac, sharedSecret, userPublicKey, peerKey);
    }

    /**
     * Calculates MAC key from given shared secret, receiver's and sender's public keys.
     *
     * @param mac MAC object to be initialized.
     * @param sharedSecret some shared secret.
     * @param receiverPublicKey receiver's public key.
     * @param senderPublicKey sender's public key.
     */
    private void initMacKey(Mac mac, byte[] sharedSecret, byte[] receiverPublicKey,
        byte[] senderPublicKey) throws InvalidKeyException {
      byte[] key = generateMacMsg(sharedSecret, receiverPublicKey, senderPublicKey);

      SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
      mac.init(keySpec);
    }

    /**
     * Generates a message for MAC by concatenating shared secret and two keys.
     *
     * @param sharedSecret some shard secret.
     * @param receiverPublicKey receiver's public key.
     * @param senderPublicKey sender's public key.
     * @return generated MAC message.
     */
    private byte[] generateMacMsg(byte[] sharedSecret, byte[] receiverPublicKey,
        byte[] senderPublicKey) {
      return ByteBuffer
          .allocate(sharedSecret.length + receiverPublicKey.length + senderPublicKey.length)
          .put(sharedSecret)
          .put(receiverPublicKey)
          .put(senderPublicKey)
          .array();
    }

  }

  private Glome(GlomeBuilder builder) {
    userPublicKey = builder.userPublicKey;
    userPrivateKey = builder.userPrivateKey;
    peerKey = builder.peerKey;
    minPeerTagLength = builder.minPeerTagLength;
    userMacKey = builder.userMac;
    peerMacKey = builder.peerMac;
  }

  public byte[] peerKey() {
    return peerKey.clone();
  }

  public byte[] userPublicKey() {
    return userPublicKey.clone();
  }

  public byte[] userPrivateKey() {
    return userPrivateKey.clone();
  }

  /**
   * Generates a user's tag corresponding to the given message {@code msg} and the counter {@code
   * cnt}.
   *
   * @param msg message from a peer.
   * @param cnt number of previously sent messages from the user to the peer.
   * @throws CounterOutOfBoundsException if {@code cnt} is out of [MIN_CNT_VALUE..MAX_CNT_VALUE]
   *     range.
   */
  public byte[] generateTag(byte[] msg, int cnt) throws CounterOutOfBoundsException {
    return generateTag(msg, cnt, userMacKey);
  }

  /**
   * Generates a tag corresponding to the given message {@code msg} and the counter {@code cnt}.
   *
   * @param msg message from a peer.
   * @param cnt number of previously sent messages from the user to the peer.
   * @param mac MAC key of a sender.
   * @throws CounterOutOfBoundsException if {@code cnt} is out of [MIN_CNT_VALUE..MAX_CNT_VALUE]
   *     range.
   */
  private byte[] generateTag(byte[] msg, int cnt, Mac mac) throws CounterOutOfBoundsException {
    if (cnt < MIN_CNT_VALUE || cnt > MAX_CNT_VALUE) {
      throw new CounterOutOfBoundsException(
          String.format(
              "Counter should be in [%d..%d] range. Got %d.",
              MIN_CNT_VALUE, MAX_CNT_VALUE, cnt
          )
      );
    }

    byte[] finalMsg = new byte[msg.length + 1];
    finalMsg[0] = (byte) cnt; // for [0..255] range do `& 0xFF`
    arraycopy(msg, 0, finalMsg, 1, msg.length);

    return mac.doFinal(finalMsg);
  }

  /**
   * Checks whether the peer's tag matches received message and some counter.
   *
   * @param peerTag tag from a peer.
   * @param msg message from a peer.
   * @param cnt number of previously sent messages from the user to the peer.
   * @throws CounterOutOfBoundsException if {@code cnt} is out of [MIN_CNT_VALUE..MAX_CNT_VALUE]
   *     range.
   * @throws WrongTagException if the peer's tag has invalid length (less than {@code
   * minPeerTagLength} or more than MAX_TAG_LENGTH) or it's not equal to the prefix of a correct
   *     tag.
   */
  public void checkTag(byte[] peerTag, byte[] msg, int cnt)
      throws CounterOutOfBoundsException, WrongTagException {
    if (peerTag.length < minPeerTagLength || peerTag.length > MAX_TAG_LENGTH) {
      throw new WrongTagException(
          String.format(
              "The received tag has invalid length. Expected value in range [%d..%d], got %d.",
              minPeerTagLength, MAX_TAG_LENGTH, peerTag.length
          )
      );
    }

    byte[] truncatedTag = Arrays.copyOf(generateTag(msg, cnt, peerMacKey), peerTag.length);
    if (!Arrays.equals(peerTag, truncatedTag)) {
      throw new WrongTagException("The received tag doesn't match the expected tag.");
    }
  }

  /**
   * Exception, which is thrown whenever a counter is out of [MIN_CNT_VALUE..MAX_CNT_VALUE] range.
   */
  public static final class CounterOutOfBoundsException extends Exception {

    CounterOutOfBoundsException(String msg) {
      super(msg);
    }

  }

  /**
   * Exception, which is thrown whenever a minimum tag length is out of
   * [MIN_TAG_LENGTH..MAX_TAG_LENGTH] range.
   */
  public static final class MinPeerTagLengthOutOfBoundsException extends Exception {

    MinPeerTagLengthOutOfBoundsException(String msg) {
      super(msg);
    }

  }

  /**
   * Exception, which is thrown whenever the received tag has invalid length or it's not equal to
   * the prefix of a correct tag.
   */
  public static final class WrongTagException extends Exception {

    WrongTagException(String msg) {
      super(msg);
    }

  }

}
