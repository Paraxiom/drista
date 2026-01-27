//! Authenticated Encryption with Associated Data (AEAD)
//!
//! Uses AES-256-GCM for symmetric encryption with authentication.

use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

/// Nonce size for AES-GCM
const NONCE_SIZE: usize = 12;

/// Encrypt plaintext with AEAD
///
/// Returns nonce || ciphertext || tag
pub fn encrypt(plaintext: &[u8], key: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::Encryption("Invalid key size".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Encryption(e.to_string()))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        })
        .map_err(|e| Error::Encryption(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend(ciphertext);

    Ok(result)
}

/// Decrypt ciphertext with AEAD
///
/// Expects nonce || ciphertext || tag
pub fn decrypt(ciphertext: &[u8], key: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::Decryption("Invalid key size".into()));
    }

    if ciphertext.len() < NONCE_SIZE + 16 {
        return Err(Error::Decryption("Ciphertext too short".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Decryption(e.to_string()))?;

    // Extract nonce
    let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let ct = &ciphertext[NONCE_SIZE..];

    // Decrypt
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: ct,
            aad: associated_data,
        })
        .map_err(|_| Error::Decryption("Decryption failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let ciphertext = encrypt(plaintext, &key, ad).unwrap();
        let decrypted = decrypt(&ciphertext, &key, ad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ad_fails() {
        let key = [0u8; 32];
        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let ciphertext = encrypt(plaintext, &key, ad).unwrap();
        let result = decrypt(&ciphertext, &key, b"wrong ad");

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; 32];
        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let mut ciphertext = encrypt(plaintext, &key, ad).unwrap();
        ciphertext[NONCE_SIZE + 5] ^= 0xFF; // Flip a byte

        let result = decrypt(&ciphertext, &key, ad);
        assert!(result.is_err());
    }
}
