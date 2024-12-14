#![no_std]
#![warn(missing_docs)]

//! # GLOME - Generic Low-Overhead Message Exchange
//!
//! GLOME is a lightweight message authentication protocol based on X25519
//! keys and HMAC-SHA256. See <https://github.com/google/glome> for details on
//! the protocol, usage patterns and implementations in other languages.
//!
//! The Rust implementation of GLOME works with its own [PrivateKey] and
//! [PublicKey] traits to support more than one backing cryptography crate.
//! It aims to provide implementations for the crates most commonly used, which
//! can be activated with the corresponding crate feature. The default and
//! recommended setting is to use [x25519_dalek]. Implementations should be
//! verified with the test vectors in the `tests` module.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// An X25519 public key.
pub trait PublicKey {
    /// to_bytes encodes the public key as a byte array according to RFC 7748.
    fn to_bytes(&self) -> [u8; 32];
}

/// An X25519 private key.
pub trait PrivateKey {
    /// PublicKey is the type of public keys corresponding to this type.
    type PublicKey: PublicKey;

    /// dh corresponds to the x25519 function from RFC 7748, computing a shared secret from a
    /// private key and a peer key.
    fn dh(&self, theirs: &Self::PublicKey) -> [u8; 32];

    /// public_key computes the public key corresponding to this private key.
    fn public_key(&self) -> Self::PublicKey;
}

/// Compute a GLOME tag.
///
/// The message counter argument `ctr` is used to prevent replay attacks in a
/// series of messages. If only a single message is exchanged between two key
/// pairs, it can be set to `0u8`. The counter value is not secret, but needs
/// to be integrity protected. Usually, this is accomplished by both parties
/// counting sent and received messages internally.
///
/// The returned tag can be verified by the
/// other party, using [verify] with its private key, our public key and the
/// counter.
pub fn tag<T: PrivateKey>(ours: &T, theirs: &T::PublicKey, ctr: u8, msg: &[u8]) -> [u8; 32] {
    let key = [
        ours.dh(theirs),
        theirs.to_bytes(),
        ours.public_key().to_bytes(),
    ]
    .concat();

    HmacSha256::new_from_slice(&key)
        .expect("HMAC can take key of any size")
        .chain_update([ctr])
        .chain_update(msg)
        .finalize()
        .into_bytes()
        .into()
}

/// Verify a GLOME tag.
///
/// This verifies tags produced by the [tag] function. The `tag` argument can
/// be shorter than the original 32 bytes, in which case the expected tag is
/// shortened to match the length of the given tag. The caller needs to ensure
/// that the tag is long enough to meet the security requirements, i.e. prevent
/// brute-forcing.
///
/// The return value is `true` if and only if the given tag matches the expected tag.
pub fn verify<T: PrivateKey>(
    ours: &T,
    theirs: &T::PublicKey,
    ctr: u8,
    msg: &[u8],
    tag: &[u8],
) -> bool {
    let key = [
        ours.dh(theirs),
        ours.public_key().to_bytes(),
        theirs.to_bytes(),
    ]
    .concat();

    HmacSha256::new_from_slice(&key)
        .expect("HMAC can take key of any size")
        .chain_update([ctr])
        .chain_update(msg)
        .verify_truncated_left(tag)
        .is_ok()
}

#[cfg(feature = "dalek")]
pub mod dalek;

#[cfg(feature = "openssl")]
pub mod openssl;

/// The [tests] module provides functions to test implementations of [PrivateKey]/[PublicKey].
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::PrivateKey;
    use hex_literal::hex;

    #[doc(hidden)]
    pub fn run_vector_1<T, F>(load_keypair: &F)
    where
        T: PrivateKey,
        F: Fn([u8; 32]) -> (T, T::PublicKey),
    {
        let (apriv, apub) = load_keypair(hex!(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        ));
        let (bpriv, bpub) = load_keypair(hex!(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        ));
        let expected = hex!("9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3");
        assert_eq!(tag(&apriv, &bpub, 0, b"The quick brown fox"), expected);
        assert_ne!(tag(&bpriv, &apub, 0, b"The quick brown fox"), expected);
        assert!(verify(
            &bpriv,
            &apub,
            0,
            b"The quick brown fox",
            &hex!("9c44389f462d")
        ));
        assert!(!verify(
            &bpriv,
            &apub,
            0,
            b"The quick brown fox",
            &hex!("ffeeddccbbaa")
        ));
        assert!(!verify(
            &apriv,
            &bpub,
            0,
            b"The quick brown fox",
            &hex!("9c44389f462d")
        ));
    }

    #[doc(hidden)]
    pub fn run_vector_2<T, F>(load_keypair: &F)
    where
        T: PrivateKey,
        F: Fn([u8; 32]) -> (T, T::PublicKey),
    {
        let (apriv, apub) = load_keypair(hex!(
            "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead"
        ));
        let (bpriv, bpub) = load_keypair(hex!(
            "b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d"
        ));
        let expected = hex!("06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277");
        assert_eq!(tag(&bpriv, &apub, 100, b"The quick brown fox"), expected);
        assert_ne!(tag(&apriv, &bpub, 100, b"The quick brown fox"), expected);
        assert!(verify(
            &apriv,
            &bpub,
            100,
            b"The quick brown fox",
            &hex!("06476f1f314b")
        ));
        assert!(!verify(
            &apriv,
            &bpub,
            100,
            b"The quick brown fox",
            &hex!("ffeeddccbbaa")
        ));
        assert!(!verify(
            &bpriv,
            &apub,
            100,
            b"The quick brown fox",
            &hex!("06476f1f314b")
        ));
    }
}
