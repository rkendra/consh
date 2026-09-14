#![allow(unused_imports)]
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use aws_lc_rs::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use ciborium::{from_reader, into_writer};
use std::io::Read;
use time::OffsetDateTime;
#[derive(PartialEq, Debug)]
pub enum ConMsg {
    Hello(Vec<u8>),
    End(Vec<u8>),
    Command(Vec<u8>),
    Error(Vec<u8>),
    Challenge {
        nonce: Vec<u8>,
        timestamp: OffsetDateTime,
        signature: Vec<u8>,
    },
}
use ConMsg::*;

impl ConMsg {
    pub const LEN_WIDTH: usize = std::mem::size_of::<usize>();
}

impl TryFrom<&[u8]> for ConMsg {
    type Error = std::io::Error;
    fn try_from(msg: &[u8]) -> Result<Self, <Self as TryFrom<&[u8]>>::Error> {
        match msg[0] {
            b'0' => Ok(Hello(msg[1..].to_vec())),
            b'1' => Ok(End(msg[1..].to_vec())),
            b'2' => Ok(Command(msg[1..].to_vec())),
            b'3' => Ok(Error(msg[1..].to_vec())),
            b'4' => {
                let mut data = &msg[1..];
                let mut len_reader = [0u8; Self::LEN_WIDTH];
                let nonce_len = match data.read_exact(&mut len_reader) {
                    Ok(_) => usize::from_be_bytes(len_reader),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid Challenge message format",
                        ));
                    }
                };
                let mut nonce = vec![0u8; nonce_len];
                data.read_exact(&mut nonce)?;

                let time_len = match data.read_exact(&mut len_reader) {
                    Ok(_) => usize::from_be_bytes(len_reader),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid Challenge message format",
                        ));
                    }
                };

                let mut time_bytes = vec![0u8; time_len];
                data.read_exact(&mut time_bytes)?;
                let timestamp: OffsetDateTime = match from_reader(time_bytes.as_slice()) {
                    Ok(stamp) => stamp,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Malformed timestamp",
                        ));
                    }
                };

                let sig_len = match data.read(&mut len_reader) {
                    Ok(_) => usize::from_be_bytes(len_reader),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid Challenge message format",
                        ));
                    }
                };

                let mut signature = vec![0u8; sig_len];
                data.read_exact(&mut signature)?;

                Ok(Challenge {
                    nonce,
                    timestamp,
                    signature,
                })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unable to parse string",
            )),
        }
    }
}

impl TryFrom<&Vec<u8>> for ConMsg {
    type Error = std::io::Error;
    fn try_from(msg: &Vec<u8>) -> Result<Self, <ConMsg as TryFrom<&Vec<u8>>>::Error> {
        Self::try_from(msg.as_slice())
    }
}

impl From<ConMsg> for Vec<u8> {
    fn from(msg: ConMsg) -> Self {
        let mut out = Vec::new();
        match &msg {
            Hello(m) => {
                let len = m.len() + 1;
                assert_eq!(len.to_be_bytes().len(), ConMsg::LEN_WIDTH);
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'0');
                out.extend_from_slice(m);
            }
            End(m) => {
                let len = m.len() + 1;
                assert_eq!(len.to_be_bytes().len(), ConMsg::LEN_WIDTH);
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'1');
                out.extend_from_slice(m);
            }
            Command(m) => {
                let len = m.len() + 1;
                assert_eq!(len.to_be_bytes().len(), ConMsg::LEN_WIDTH);
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'2');
                out.extend_from_slice(m);
            }
            Error(m) => {
                let len = m.len() + 1;
                assert_eq!(len.to_be_bytes().len(), ConMsg::LEN_WIDTH);
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'3');
                out.extend_from_slice(m);
            }
            Challenge {
                nonce,
                timestamp,
                signature,
            } => {
                let mut time_bytes = Vec::new();
                let _ = into_writer(&timestamp, &mut time_bytes);
                let len =
                    nonce.len() + time_bytes.len() + signature.len() + 1 + ConMsg::LEN_WIDTH * 3;
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'4');
                out.extend_from_slice(&nonce.len().to_be_bytes());
                out.extend_from_slice(nonce);
                out.extend_from_slice(&time_bytes.len().to_be_bytes());
                out.extend_from_slice(&time_bytes);
                out.extend_from_slice(&signature.len().to_be_bytes());
                out.extend_from_slice(signature);
            }
        }
        out
    }
}

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

pub mod auth {
    use super::ConMsg;
    use aws_lc_rs::{
        error::Unspecified,
        rand,
        signature::{
            PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm, UnparsedPublicKey,
        },
    };
    use std::io::prelude::*;
    use std::net::TcpStream;

    pub fn receive_key(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut len_bytes = [0u8; ConMsg::LEN_WIDTH];
        sock.read_exact(&mut len_bytes)?;
        let msg_len = usize::from_be_bytes(len_bytes);
        let mut msg = vec![0u8; msg_len];
        sock.read_exact(&mut msg)?;
        let peer_key = match ConMsg::try_from(&msg) {
            Ok(con_msg) => match con_msg {
                ConMsg::Hello(key) => key,
                _ => {
                    let error_msg: Vec<u8> =
                        ConMsg::Error(Vec::from(b"Bad handshake opener")).into();
                    sock.write_all(&error_msg)?;
                    return Err(std::io::Error::other("Handshake failed"));
                }
            },
            Err(e) => {
                return Err(e);
            }
        };
        Ok(peer_key)
    }

    /// Challenge the party connected to sock on ownership of pub_key
    /// Returns Ok(()) if and only if no communication error occured, and key ownership is verified
    /// Communication errors will be of type std::io::Error, while validation errors will be of
    /// aws_lc_rs::error::Unspecified
    ///
    /// Peers being challenged by this function should call verify() to properly respond
    pub fn challenge(
        sock: &mut TcpStream,
        pub_key: &Vec<u8>,
        algorithm: &'static PqdsaVerificationAlgorithm,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pub_key = UnparsedPublicKey::new(algorithm, pub_key);
        let mut nonce = [0u8; 12];
        aws_lc_rs::rand::fill(&mut nonce)?;

        let challenge = ConMsg::Challenge {
            nonce: Vec::from(nonce),
            timestamp: time::OffsetDateTime::now_utc(),
            signature: vec![0u8; 1],
        };
        sock.write_all(&Vec::from(challenge))?;

        // Verify signature from client
        let mut len_bytes = [0u8; ConMsg::LEN_WIDTH];
        sock.read_exact(&mut len_bytes)?;
        let msg_len = usize::from_be_bytes(len_bytes);
        let mut msg = vec![0u8; msg_len];
        sock.read_exact(&mut msg)?;
        let challenge = match ConMsg::try_from(&msg) {
            Ok(con_msg) => match con_msg {
                ConMsg::Challenge {
                    nonce,
                    timestamp,
                    signature,
                } => (nonce, timestamp, signature),
                _ => {
                    let error_msg: Vec<u8> =
                        ConMsg::Error(Vec::from(b"Malformed signature message")).into();
                    sock.write_all(&error_msg)?;
                    return Err(Box::new(std::io::Error::other("Handshake failed")));
                }
            },
            Err(e) => {
                return Err(Box::new(e));
            }
        };
        // Verify that the nonce was the one generated, reject otherwise
        if challenge.0 != nonce {
            // Close the connection w/o notifying client
            return Err(Box::new(Unspecified {}));
        }

        pub_key.verify(&challenge.0, &challenge.2)?;
        Ok(())
    }

    pub fn prove(
        sock: &mut TcpStream,
        key: PqdsaKeyPair,
        algorithm: &'static PqdsaSigningAlgorithm,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut len_bytes = [0u8; ConMsg::LEN_WIDTH];
        sock.read_exact(&mut len_bytes)?;
        let msg_len = usize::from_be_bytes(len_bytes);
        let mut challenge = vec![0u8; msg_len];
        sock.read_exact(&mut challenge)?;
        let challenge = match ConMsg::try_from(&challenge)? {
            ConMsg::Challenge {
                nonce,
                timestamp,
                signature,
            } => (nonce, timestamp, signature),
            _ => {
                return Err(Box::new(std::io::Error::other(
                    "Malformed challenge response from server",
                )));
            }
        };

        let mut signature = vec![0u8; algorithm.signature_len()];
        key.sign(&challenge.0, &mut signature)?;

        let response = ConMsg::Challenge {
            nonce: challenge.0,
            timestamp: challenge.1,
            signature,
        };

        sock.write_all(&Vec::from(response))?;
        Ok(())
    }
}

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
