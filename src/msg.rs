use ciborium::{from_reader, into_writer};
use std::io::prelude::*;
use time::OffsetDateTime;

#[derive(PartialEq, Debug)]
pub enum ConMsg {
    Hello(Vec<u8>),
    Encapsulation(Vec<u8>),
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

            b'5' => Ok(Encapsulation(msg[1..].to_vec())),

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

            Encapsulation(m) => {
                let len = m.len() + 1;
                assert_eq!(len.to_be_bytes().len(), ConMsg::LEN_WIDTH);
                out.extend_from_slice(&len.to_be_bytes());
                out.push(b'5');
                out.extend_from_slice(m);
            }
        }
        out
    }
}
