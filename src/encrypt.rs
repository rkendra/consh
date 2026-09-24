use crate::ConMsg;
use crate::auth::{challenge, prove, receive_key};
use aws_lc_rs::cipher::AES_256_KEY_LEN;
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

pub struct EncryptListener(TcpListener);

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
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut sock = TcpStream::connect(addr)?;
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
            ConMsg::Encapsulation(bytes) => bytes,
            _ => {
                return Err(Box::new(std::io::Error::other(
                    "Server did not follow protocol",
                )));
            }
        };

        let cipher = decap.decapsulate(Ciphertext::from(cipher.as_ref()))?;
        let cipher = cipher.as_ref();

        let info = b"consh-client";
        let mut send_key = vec![0u8; AES_256_GCM.key_len()];
        let kdf_digest = match get_sskdf_digest_algorithm(SskdfDigestAlgorithmId::Sha256) {
            Some(digest) => digest,
            None => {
                return Err(Box::new(aws_lc_rs::error::Unspecified {}));
            }
        };
        sskdf_digest(kdf_digest, cipher, info, &mut send_key)?;
        let send_key = RandomizedNonceKey::new(&AES_256_GCM, &send_key)?;

        sock.read_exact(&mut len_bytes)?;
        let msg_len = usize::from_be_bytes(len_bytes);
        msg = vec![0u8; msg_len];
        sock.read_exact(&mut msg)?;
        let encap_bytes = match ConMsg::try_from(&msg)? {
            ConMsg::Hello(bytes) => bytes,
            _ => {
                return Err(Box::new(std::io::Error::other(
                    "Server did not follow protocol",
                )));
            }
        };
        let encap = EncapsulationKey::new(&ML_KEM_1024, &encap_bytes)?;
        let (cipher, server_secret) = encap.encapsulate()?;

        sock.write_all(cipher.as_ref())?;
        let mut recv_key = vec![0u8; AES_256_KEY_LEN];
        sskdf_digest(kdf_digest, server_secret.as_ref(), info, &mut recv_key)?;

        let recv_key = RandomizedNonceKey::new(&AES_256_GCM, &recv_key)?;

        Ok(EncryptStream {
            inner: sock,
            send_key,
            recv_key,
            algo: AES_256_GCM,
            cipher_buf: Vec::new(),
            recv_buf: Vec::new(),
            decrypt_buf: Vec::new(),
        })
    }
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
        let expected_winsize =
            buf.len() + self.algo.nonce_len() + self.algo.tag_len() + size_of::<usize>();
        let bytes_to_recv: usize;
        if !self.recv_buf.is_empty() {
            if self.recv_buf.len() < size_of::<usize>() {
                bytes_to_recv = expected_winsize - self.recv_buf.len();
            } else {
                bytes_to_recv =
                    usize::from_be_bytes(self.recv_buf[..size_of::<usize>()].try_into().unwrap())
                        - self.recv_buf.len();
            }
        } else {
            bytes_to_recv = expected_winsize;
        }

        let mut msg = vec![0u8; bytes_to_recv];
        let bytes_read = self.inner.read(&mut msg)?;
        self.recv_buf.extend_from_slice(&msg);

        if bytes_read < bytes_to_recv {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Did not receive entire frame",
            ));
        }

        let msg_nolen = &mut msg[size_of::<usize>()..];
        let (nonce, ctext) = msg_nolen.split_at_mut(self.algo.nonce_len());
        let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce).unwrap();
        let ptext = match self.recv_key.open_in_place(nonce, Aad::empty(), ctext) {
            Ok(res) => res,
            Err(_) => {
                return Err(std::io::Error::other("Invalid ciphertext"));
            }
        };

        let mut writer = buf;
        let written = writer.write(ptext)?;
        if written < ptext.len() {
            self.decrypt_buf.extend_from_slice(&ptext[written..]);
        }
        Ok(written)
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
        let nonce = self
            .send_key
            .seal_in_place_append_tag(Aad::empty(), &mut seal);
        match nonce {
            Ok(n_bytes) => {
                let frame_len = self.algo.nonce_len() + seal.len();
                raw_buf.extend_from_slice(&frame_len.to_be_bytes());
                raw_buf.extend_from_slice(n_bytes.as_ref());
                raw_buf.extend_from_slice(&seal);
                let bytes_written = self.inner.write(buf)?;
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
                    self.flush()?;
                    buf = &buf[n..];
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl EncryptListener {
    pub fn as_inner(&self) -> &TcpListener {
        &self.0
    }

    pub fn as_inner_mut(&mut self) -> &mut TcpListener {
        &mut self.0
    }
}
