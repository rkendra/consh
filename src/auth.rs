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
                let error_msg: Vec<u8> = ConMsg::Error(Vec::from(b"Bad handshake opener")).into();
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
