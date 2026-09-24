#![allow(unused_imports)]
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::signature::{
    ED25519, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, UnparsedPublicKey,
};
use aws_lc_rs::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use ciborium::{from_reader, into_writer};
use std::io::Read;
use time::OffsetDateTime;

pub(crate) mod auth;
mod encrypt;
mod msg;

pub use encrypt::*;
pub use msg::*;

#[derive(Clone, Debug)]
pub struct SigPublicKey {
    trad_key_bytes: aws_lc_rs::signature::Ed25519PublicKey,
    pqc_key_bytes: aws_lc_rs::signature::PqdsaPublicKey,
}

impl SigPublicKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        [self.trad_key_bytes.as_ref(), self.pqc_key_bytes.as_ref()].concat()
    }

    pub fn verify(&self, msg: &[u8], ed_sig: &[u8], pqc_sig: &[u8]) -> Result<(), Unspecified> {
        let ed_key = UnparsedPublicKey::new(&ED25519, self.trad_key_bytes.as_ref());
        let pqc_key = UnparsedPublicKey::new(&ML_DSA_44, self.pqc_key_bytes.as_ref());
        ed_key.verify(msg, ed_sig)?;
        pqc_key.verify(msg, pqc_sig)
    }
}

pub(crate) enum PqKeyAlgorithm {
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

impl PqKeyAlgorithm {
    pub fn signing(&self) -> &aws_lc_rs::signature::PqdsaSigningAlgorithm {
        match self {
            PqKeyAlgorithm::MLDSA44 => &ML_DSA_44_SIGNING,
            PqKeyAlgorithm::MLDSA65 => &ML_DSA_65_SIGNING,
            PqKeyAlgorithm::MLDSA87 => &ML_DSA_87_SIGNING,
        }
    }

    pub fn validating(&self) -> &aws_lc_rs::signature::PqdsaVerificationAlgorithm {
        match self {
            PqKeyAlgorithm::MLDSA44 => &ML_DSA_44,
            PqKeyAlgorithm::MLDSA65 => &ML_DSA_65,
            PqKeyAlgorithm::MLDSA87 => &ML_DSA_87,
        }
    }
}

pub(crate) enum AEADAlgorithm {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_to_vec() {
        let one: ConMsg = ConMsg::Hello(Vec::from(b"a"));
        let two: ConMsg = ConMsg::End(Vec::from(b"ab"));
        let three: ConMsg = ConMsg::Command(Vec::from(b"abc"));
        let four: ConMsg = ConMsg::Error(Vec::from(b"abcd"));
        assert_eq!(
            Vec::from(one),
            vec![b'\x00', b'\x00', b'\x00', b'\x02', b'0', b'a']
        );
        assert_eq!(
            Vec::from(two),
            vec![b'\x00', b'\x00', b'\x00', b'\x03', b'1', b'a', b'b']
        );
        assert_eq!(
            Vec::from(three),
            vec![b'\x00', b'\x00', b'\x00', b'\x04', b'2', b'a', b'b', b'c']
        );
        assert_eq!(
            Vec::from(four),
            vec![
                b'\x00', b'\x00', b'\x00', b'\x05', b'3', b'a', b'b', b'c', b'd'
            ]
        );
    }

    #[test]
    fn str_to_msg() {
        let one: ConMsg = ConMsg::Hello(Vec::from(b"a"));
        let two: ConMsg = ConMsg::End(Vec::from(b"ab"));
        let three: ConMsg = ConMsg::Command(Vec::from(b"abc"));
        let four: ConMsg = ConMsg::Error(Vec::from(b"abcd"));
        assert_eq!(one, ConMsg::try_from(b"2:0a" as &[u8]).unwrap());
        assert_eq!(two, ConMsg::try_from(b"3:1ab" as &[u8]).unwrap());
        assert_eq!(three, ConMsg::try_from(b"4:2abc" as &[u8]).unwrap());
        assert_eq!(four, ConMsg::try_from(b"5:3abcd" as &[u8]).unwrap());
    }
}
