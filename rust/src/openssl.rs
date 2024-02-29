//! [PrivateKey] and [PublicKey] implementations for types in [openssl].
//!
//! Although X25519 is specified to never need exception handling, the openssl
//! crate returns [Result] values. The implementations in this module panic on
//! returned errors.
//!
//! Usage example:
//!
//! ```
//! use hex_literal::hex;
//! use openssl::pkey;
//! use glome::{tag,verify};
//!
//! let raw_private_key = [15u8; 32]; // <- our private key loaded from somewhere
//! let private_key = pkey::PKey::private_key_from_raw_bytes(&raw_private_key, pkey::Id::X25519).unwrap();
//! let raw_public_key = [16u8; 32]; // <- their public key loaded from somewhere
//! let public_key = pkey::PKey::public_key_from_raw_bytes(&raw_public_key, pkey::Id::X25519).unwrap();
//!
//! let alice_raw_private_key = hex!("fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead");
//! let alice_private_key = pkey::PKey::private_key_from_raw_bytes(&alice_raw_private_key, pkey::Id::X25519).unwrap();
//! let alice_raw_public_key = hex!("872f435bb8b89d0e3ad62aa2e511074ee195e1c39ef6a88001418be656e3c376");
//! let alice_public_key = pkey::PKey::public_key_from_raw_bytes(&alice_raw_public_key, pkey::Id::X25519).unwrap();
//!
//! let bob_raw_private_key = hex!("b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d");
//! let bob_private_key = pkey::PKey::private_key_from_raw_bytes(&bob_raw_private_key, pkey::Id::X25519).unwrap();
//! let bob_raw_public_key = hex!("d1b6941bba120bcd131f335da15778d9c68dadd398ae61cf8e7d94484ee65647");
//! let bob_public_key = pkey::PKey::public_key_from_raw_bytes(&bob_raw_public_key, pkey::Id::X25519).unwrap();
//!
//! let msg = b"Hello, world!";
//! let t = tag(&alice_private_key, &bob_public_key, 0u8, msg);
//! assert!(verify(&bob_private_key, &alice_public_key, 0u8, msg, &t));
//! assert!(!verify(&bob_private_key, &alice_public_key, 0u8, b"kthxbai", &t));
//! ```

use openssl::{derive, pkey};

use crate::{PrivateKey, PublicKey};

impl PublicKey for pkey::PKey<pkey::Public> {
    fn to_bytes(&self) -> [u8; 32] {
        self.raw_public_key()
            .expect("an X25519 key should be convertible to bytes")
            .try_into()
            .expect("raw public key should be 32 bytes long")
    }
}

impl PrivateKey for pkey::PKey<pkey::Private> {
    type PublicKey = pkey::PKey<pkey::Public>;

    fn dh(&self, theirs: &Self::PublicKey) -> [u8; 32] {
        let mut deriver = derive::Deriver::new(self)
            .expect("should be able to create a deriver from an X25519 key");
        deriver
            .set_peer(theirs)
            .expect("should be able to set an X25519 public key as peer");

        let mut secret = [0u8; 32];
        let n = deriver
            .derive(&mut secret)
            .expect("should be able to derive shared secret");
        assert_eq!(n, 32);
        secret
    }

    fn public_key(&self) -> Self::PublicKey {
        // TODO(burgerdev): is there a proper API for this?
        let b: [u8; 32] = self
            .raw_public_key()
            .expect("an X25519 key should be convertible to bytes")
            .try_into()
            .expect("raw public key should be 32 bytes long");
        pkey::PKey::public_key_from_raw_bytes(&b, pkey::Id::X25519).expect("TODO")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{run_vector_1, run_vector_2};

    fn load_keypair(b: [u8; 32]) -> (pkey::PKey<pkey::Private>, pkey::PKey<pkey::Public>) {
        let secret = pkey::PKey::private_key_from_raw_bytes(&b, pkey::Id::X25519).unwrap();
        let public = secret.public_key();
        (secret, public)
    }

    #[test]
    fn test_vector_1() {
        run_vector_1(&load_keypair);
    }

    #[test]
    fn test_vector_2() {
        run_vector_2(&load_keypair);
    }
}
