package com.google.jglome;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * A helper class to generate input data from GLOME test vectors.
 */
public class TestVector {

  private byte[] ka; // A's public key
  private byte[] kb; // B's public key
  private byte[] kah; // A's ephemeral private key
  private byte[] kbh; // B's private key
  private byte[] ks; // shared secret
  private byte[] tag; // generated tag
  private byte[] msg; // message to be sent
  private int cnt; // counter of messaged that has been sent from the sending side to the receiving

  public byte[] getKa() {
    return ka;
  }

  public byte[] getKb() {
    return kb;
  }

  public byte[] getKah() {
    return kah;
  }

  public byte[] getKbh() {
    return kbh;
  }

  public byte[] getKs() {
    return ks;
  }

  public byte[] getTag() {
    return tag;
  }

  public byte[] getMsg() {
    return msg;
  }

  public int getCnt() {
    return cnt;
  }

  TestVector(String ka, String kb, String kah, String kbh, String tag, String ks, String msg,
      int cnt) {
    this.ka = fromHexString(ka);
    this.kb = fromHexString(kb);
    this.kah = fromHexString(kah);
    this.kbh = fromHexString(kbh);
    this.ks = fromHexString(ks);
    this.tag = fromHexString(tag);
    this.msg = msg.getBytes(UTF_8);
    this.cnt = cnt;
  }

  private static byte[] fromHexString(String str) {
    // add a specific byte value as a prefix in case of leading zeros
    byte[] bytes = new BigInteger("10" + str.replaceAll("\\s", ""), 16).toByteArray();
    return Arrays.copyOfRange(bytes, 1, bytes.length); // remove first fake byte
  }

  // Message from Alice to Bob.
  final static TestVector testVector1 = new TestVector(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
      "9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3",
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
      "The quick brown fox",
      0
  );

  // Message from Bob to Alice.
  final static TestVector testVector2 = new TestVector(
      "872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376",
      "d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647",
      "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead",
      "b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d",
      "06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277",
      "4b1ee05fcd2ae53ebe4c9ec94915cb057109389a2aa415f26986bddebf379d67",
      "The quick brown fox",
      100
  );

  final static List<TestVector> TEST_VECTORS = List.of(testVector1, testVector2);

}
