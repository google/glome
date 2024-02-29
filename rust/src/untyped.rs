use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

type HmacSha256 = Hmac<Sha256>;

pub fn tag(ours: &[u8; 32], theirs: &[u8; 32], ctr: u8, msg: &[u8]) -> [u8; 32] {
    let secret = x25519(ours.clone(), theirs.clone());

    compute_hmac(&secret, &pub_of_secret(ours), theirs, ctr, msg)
        .finalize()
        .into_bytes()
        .into()
}

pub fn verify(ours: &[u8; 32], theirs: &[u8; 32], ctr: u8, msg: &[u8], tag: &[u8]) -> bool {
    let secret = x25519(ours.clone(), theirs.clone());

    compute_hmac(&secret, theirs, &pub_of_secret(ours), ctr, msg)
        .verify_truncated_left(tag)
        .is_ok()
}

fn pub_of_secret(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret.clone(), X25519_BASEPOINT_BYTES)
}

fn compute_hmac(
    secret: &[u8; 32],
    from: &[u8; 32],
    to: &[u8; 32],
    ctr: u8,
    msg: &[u8],
) -> HmacSha256 {
    let key = [secret.as_slice(), to.as_slice(), from.as_slice()].concat();

    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(&[ctr]);
    mac.update(msg);
    mac
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    struct KeyPair {
        sk: [u8; 32],
        pk: [u8; 32]
    }

    fn keypair(secret: [u8; 32]) -> KeyPair {
        KeyPair { sk: secret, pk: pub_of_secret(&secret) }
    }

    #[test]
    fn test_vector_1() {
        let a = keypair(hex!(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        ));
        let b = keypair(hex!(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        ));
        let expected = hex!("9c44389f462d35d0672faf73a5e118f8b9f5c340bbe8d340e2b947c205ea4fa3");
        assert_eq!(
            tag(&a.sk, &b.pk, 0, b"The quick brown fox"),
            expected
        );
        assert_ne!(
            tag(&b.sk, &a.pk, 0, b"The quick brown fox"),
            expected
        );
        assert_eq!(
            verify(
                &b.sk,
                &a.pk,
                0,
                b"The quick brown fox",
                &hex!("9c44389f462d")
            ),
            true
        );
        assert_eq!(
            verify(
                &b.sk,
                &a.pk,
                0,
                b"The quick brown fox",
                &hex!("ffeeddccbbaa")
            ),
            false
        );
        assert_eq!(
            verify(
                &a.sk,
                &b.pk,
                0,
                b"The quick brown fox",
                &hex!("9c44389f462d")
            ),
            false
        );
    }

    #[test]
    fn test_vector_2() {
        let a = keypair(hex!(
            "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead"
        ));
        let b = keypair(hex!(
            "b105f00db105f00db105f00db105f00db105f00db105f00db105f00db105f00d"
        ));
        let expected = hex!("06476f1f314b06c7f96e5dc62b2308268cbdb6140aefeeb55940731863032277");
        assert_eq!(
            tag(&b.sk, &a.pk, 100, b"The quick brown fox"),
            expected
        );
        assert_ne!(
            tag(&a.sk, &b.pk, 100, b"The quick brown fox"),
            expected
        );
        assert_eq!(
            verify(
                &a.sk,
                &b.pk,
                100,
                b"The quick brown fox",
                &hex!("06476f1f314b")
            ),
            true
        );
        assert_eq!(
            verify(
                &a.sk,
                &b.pk,
                100,
                b"The quick brown fox",
                &hex!("ffeeddccbbaa")
            ),
            false
        );
        assert_eq!(
            verify(
                &b.sk,
                &a.pk,
                100,
                b"The quick brown fox",
                &hex!("06476f1f314b")
            ),
            false
        );
    }
}