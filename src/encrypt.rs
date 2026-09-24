use crate::ConMsg;
use crate::auth::{challenge, prove, receive_key};
use aws_lc_rs::rand::Random;
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, Algorithm, RandomizedNonceKey},
    kdf::{SskdfDigestAlgorithm, SskdfDigestAlgorithmId, get_sskdf_digest_algorithm, sskdf_digest},
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024},
    signature::PqdsaKeyPair,
};

use std::io::copy;
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

pub struct EncryptStream {
    inner: TcpStream,
    send_key: RandomizedNonceKey,
    recv_key: RandomizedNonceKey,
    algo: Algorithm,
    cipher_buf: Vec<u8>,
    decrypt_buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

pub struct EncryptListener {
    inner: TcpListener,
    id: PqdsaKeyPair,
}

pub trait KeyValidate {
    type Error;

    fn validate(&self, key: &[u8]) -> Result<(), Self::Error>;
}

impl<F: Fn(&[u8]) -> Result<(), E>, E> KeyValidate for F {
    type Error = E;

    fn validate(&self, key: &[u8]) -> Result<(), E> {
        self(key)
    }
}

impl EncryptStream {
    pub fn connect<A: ToSocketAddrs, K: KeyValidate>(
        addr: A,
        algo: super::PqKeyAlgorithm,
    ) -> Result<Self, Box<dyn std::error::Error>> {

        // Perform identity check of key, if specified, then validate public keys
        let mut sock = TcpStream::connect(addr)?;
        let server_key = receive_key(&mut sock)?;
        if let Some(validator) = validator {
            let result = validator.validate(&server_key);
        }
        challenge(&mut sock, &server_key, algo.validating())?;
        prove(&mut sock, id, algo.signing())?;

        // Perform Key Encapsulation
        let decap = DecapsulationKey::generate(&ML_KEM_1024)?;
        let encap = decap.encapsulation_key()?;
        let encap_bytes = encap.key_bytes()?;
        let encap_bytes = encap_bytes.as_ref();
        let init_msg = ConMsg::Hello(Vec::from(encap_bytes));

        sock.write_all(&Vec::from(init_msg))?;

        // Derive shared secret from server
        let mut len_bytes = [0u8; ConMsg::LEN_WIDTH];
        sock.read_exact(&mut len_bytes)?;
        let msg_len = usize::from_be_bytes(len_bytes);
        let mut msg = vec![0u8; msg_len];
        sock.read_exact(&mut msg)?;

        let cipher = match ConMsg::try_from(&msg)? {
            ConMsg::Hello(bytes) => bytes,
            _ => {
                return Err(Box::new(std::io::Error::other(
                    "Server did not follow protocol",
                )));
            }
        };

        let cipher = decap.decapsulate(Ciphertext::from(cipher))?;
        let cipher = cipher.as_ref();

        let 

    }

    fn gen_send_key()
}

impl Read for EncryptStream {
    /// Read an encrypted frame from the underlying TcpStream, writing the decrypted output into buf
    /// Buffers decrypted output if buf.len() is smaller than the decrypted output receive_key
    /// Initially attempts to read a frame for a message of length buf.len() adjusting as necessary
    ///
    /// If decrypted data is waiting to be read, no call to the underlying TcpStream will be made,
    /// and the remaining contents of the buffer will be filled into buf instead.
    ///
    /// If the underlying call to TcpStream::read does not provide an entire decryptable frame, this
    /// will return an error of ErrorKind::Interrupted. In this case, ciphertext will be buffered,
    /// and the operation should be retried. Errors of all other types are forwarded from the
    /// underlying call
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.decrypt_buf.is_empty() {
            let mut copier = buf;
            if copier.len() < self.decrypt_buf.len() {
                let bytes_written = copier.write(&self.decrypt_buf)?;
                let new_buf = Vec::from(&self.decrypt_buf[bytes_written..]);
                self.decrypt_buf = new_buf;
                return Ok(bytes_written);
            } else {
                let bytes_written = copier.write(&self.decrypt_buf)?;
                self.decrypt_buf.clear();
                return Ok(bytes_written);
            }
        }
        if self.

        Ok(buf.len())
    }
}

impl Write for EncryptStream {
    /// Encrypt the input in buf and write the result of the operation to the underlying TcpStream
    /// in the following form: nonce || ciphertext || tag
    ///
    /// In non-error circumstances, this returns 'Ok' with the value either being buf.len()
    /// if encryption succeeds, or 0 if there was remaining ciphertext from the previous encryption
    /// that needed to be consumed
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        if !self.cipher_buf.is_empty() {
            let mut to_clear = self.cipher_buf.as_slice();
            copy(&mut to_clear, &mut self.inner)?;
            self.cipher_buf.clear();
            return Ok(0);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let mut raw_buf = Vec::new();
        let mut seal = buf.to_vec();
        let nonce = self.key.seal_in_place_append_tag(Aad::empty(), &mut seal);
        match nonce {
            Ok(n_bytes) => {
                let frame_len = self.algo.nonce_len() + seal.len();
                raw_buf.extend_from_slice(&frame_len.to_be_bytes());
                raw_buf.extend_from_slice(n_bytes.as_ref());
                raw_buf.extend_from_slice(&seal);
                let bytes_written = self.inner.write(&buf)?;
                self.cipher_buf.extend_from_slice(&raw_buf[bytes_written..]);
                Ok(buf.len())
            }
            Err(_) => Err(std::io::Error::other("Encryption failed")),
        }
    }

    /// Clears any buffered ciphertext from the stream, writing the buffer into the innner TcpStream
    ///
    /// Calling this method on a stream with an empty buffer is essentially a no-op
    /// This call may result in multiple write() calls to the underlying TcpStream
    fn flush(&mut self) -> Result<(), std::io::Error> {
        let mut bytes_written = 0usize;
        while bytes_written < self.cipher_buf.len() {
            bytes_written += self.inner.write(&self.cipher_buf[bytes_written..])?;
        }
        Ok(())
    }

    /// Encrypts and writes the entire buffer to the underlying TcpStream
    ///
    /// This functions nearly identically to the default write_all provided by libstd,
    /// but ensures the buffer is flushed after each successful write to prevent unintended EOF errors
    /// due to the implementation of write()
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), std::io::Error> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Unable to write entire buffer",
                    ));
                }
                Ok(n) => {
                    self.flush();
                    buf = &buf[n..];
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
