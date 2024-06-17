//! [PrivateKey] and [PublicKey] implementations for types in [x25519_dalek].
//!
//! Usage example:
//!
//! ```
//! use hex_literal::hex;
//! use x25519_dalek::{PublicKey, StaticSecret};
//! use glome::{tag,verify};
//!
//! let alice_private_key: StaticSecret = hex!("fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead").into();
//! let alice_public_key: PublicKey = (&alice_private_key).into();
//!
//! let bob_private_key: StaticSecret = hex!("b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d").into();
//! let bob_public_key: PublicKey = (&bob_private_key).into();
//!
//! let msg = b"Hello, world!";
//! let t = tag(&alice_private_key, &bob_public_key, 0u8, msg);
//! assert!(verify(&bob_private_key, &alice_public_key, 0u8, msg, &t));
//! assert!(!verify(&bob_private_key, &alice_public_key, 0u8, b"kthxbai", &t));
//! ```

use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};

use crate::{PrivateKey, PublicKey};

impl PublicKey for DalekPublicKey {
    fn to_bytes(&self) -> [u8; 32] {
        self.to_bytes()
    }
}

impl PrivateKey for StaticSecret {
    type PublicKey = DalekPublicKey;

    fn dh(&self, theirs: &Self::PublicKey) -> [u8; 32] {
        self.diffie_hellman(theirs).to_bytes()
    }

    fn public_key(&self) -> Self::PublicKey {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{run_vector_1, run_vector_2};

    fn keypair(b: [u8; 32]) -> (StaticSecret, DalekPublicKey) {
        let secret: StaticSecret = b.into();
        let public: DalekPublicKey = (&secret).into();
        (secret, public)
    }

    #[test]
    fn test_vector_1() {
        run_vector_1(&keypair)
    }

    #[test]
    fn test_vector_2() {
        run_vector_2(&keypair)
    }
}
