#![allow(unused_imports)]
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
use aws_lc_rs::unstable::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
#[derive(PartialEq, Debug)]
pub enum ConMsg {
    Hello(String),
    End(String),
    Command(String),
    Error(String),
    Timeout(String),
}
use ConMsg::*;

impl ConMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Hello(m) => {
                let len = u32::try_from(m.len() + 1).expect("How is your command over 4 gigabytes?");
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'0');
                out.extend_from_slice(m.as_bytes());
            },
            End(m) => {
                let len = u32::try_from(m.len() + 1).expect("How is your command over 4 gigabytes?");
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'1');
                out.extend_from_slice(m.as_bytes());
            },
            Command(m) => {
                let len = u32::try_from(m.len() + 1).expect("How is your command over 4 gigabytes?");
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'2');
                out.extend_from_slice(m.as_bytes());
            },
            Error(m) => {
                let len = u32::try_from(m.len() + 1).expect("How is your command over 4 gigabytes?");
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'3');
                out.extend_from_slice(m.as_bytes());
            },
            Timeout(m) => {
                let len = u32::try_from(m.len() + 1).expect("How is your command over 4 gigabytes?");
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'4');
                out.extend_from_slice(m.as_bytes());
            },
        }
        out
    }

    pub fn from_bytes(msg: String) -> std::io::Result<ConMsg> {
        match msg.chars().nth(0) {
            Some('0') => Ok(Hello(msg[1..].to_string())),
            Some('1') => Ok(End(msg[1..].to_string())),
            Some('2') => Ok(Command(msg[1..].to_string())),
            Some('3') => Ok(Error(msg[1..].to_string())),
            Some('4') => Ok(Timeout(msg[1..].to_string())),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unable to parse string")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SigPublicKey {
    trad_key_bytes: aws_lc_rs::signature::Ed25519PublicKey,
    pqc_key_bytes: aws_lc_rs::unstable::signature::PqdsaPublicKey,
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




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_to_vec() {
        let one: ConMsg = ConMsg::Hello(String::from("a"));
        let two: ConMsg = ConMsg::End(String::from("ab"));
        let three: ConMsg = ConMsg::Command(String::from("abc"));
        let four: ConMsg = ConMsg::Error(String::from("abcd"));
        let five: ConMsg = ConMsg::Timeout(String::from("abcde"));
        assert_eq!(one.to_bytes(), vec![b'\x00', b'\x00', b'\x00', b'\x02', b'0', b'a']);
        assert_eq!(two.to_bytes(), vec![b'\x00', b'\x00', b'\x00', b'\x03', b'1', b'a', b'b']);
        assert_eq!(three.to_bytes(), vec![b'\x00', b'\x00', b'\x00', b'\x04', b'2', b'a', b'b', b'c']);
        assert_eq!(four.to_bytes(), vec![b'\x00', b'\x00', b'\x00', b'\x05', b'3', b'a', b'b', b'c', b'd']);
        assert_eq!(five.to_bytes(), vec![b'\x00', b'\x00', b'\x00', b'\x06', b'4', b'a', b'b', b'c', b'd', b'e']);
    }

    #[test]
    fn str_to_msg() {
        let one: ConMsg = ConMsg::Hello(String::from("a"));
        let two: ConMsg = ConMsg::End(String::from("ab"));
        let three: ConMsg = ConMsg::Command(String::from("abc"));
        let four: ConMsg = ConMsg::Error(String::from("abcd"));
        let five: ConMsg = ConMsg::Timeout(String::from("abcde"));
        assert_eq!(one, ConMsg::from_bytes(String::from("2:0a")).unwrap());
        assert_eq!(two, ConMsg::from_bytes(String::from("3:1ab")).unwrap());
        assert_eq!(three, ConMsg::from_bytes(String::from("4:2abc")).unwrap());
        assert_eq!(four, ConMsg::from_bytes(String::from("5:3abcd")).unwrap());
        assert_eq!(five, ConMsg::from_bytes(String::from("6:4abcde")).unwrap());
    }
}
