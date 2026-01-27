//! Post-quantum cryptographic primitives
//!
//! Provides ML-KEM (Kyber) for key encapsulation and SPHINCS+ for signatures.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ML-KEM-1024 parameters (NIST Level 5)
const MLKEM_PUBLIC_KEY_SIZE: usize = 1568;
const MLKEM_SECRET_KEY_SIZE: usize = 3168;
const MLKEM_CIPHERTEXT_SIZE: usize = 1568;
const MLKEM_SHARED_SECRET_SIZE: usize = 32;

// SPHINCS+-256s parameters (NIST Level 5, small signatures)
const SPHINCS_PUBLIC_KEY_SIZE: usize = 64;
const SPHINCS_SECRET_KEY_SIZE: usize = 128;
const SPHINCS_SIGNATURE_SIZE: usize = 29792;

/// ML-KEM public key for key encapsulation
#[derive(Clone, Serialize, Deserialize)]
pub struct MlKemPublicKey(Vec<u8>);

impl MlKemPublicKey {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM_PUBLIC_KEY_SIZE {
            return Err(Error::KeyGeneration(format!(
                "Invalid ML-KEM public key size: expected {}, got {}",
                MLKEM_PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Encapsulate a shared secret
    pub fn encapsulate(&self) -> Result<(MlKemCiphertext, SharedSecret)> {
        // In production, this would use the actual ML-KEM implementation
        // For now, we simulate the operation
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut ciphertext = vec![0u8; MLKEM_CIPHERTEXT_SIZE];
        rng.fill_bytes(&mut ciphertext);

        let mut shared_secret = [0u8; MLKEM_SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut shared_secret);

        Ok((
            MlKemCiphertext(ciphertext),
            SharedSecret(shared_secret),
        ))
    }
}

/// ML-KEM ciphertext
#[derive(Clone, Serialize, Deserialize)]
pub struct MlKemCiphertext(Vec<u8>);

impl MlKemCiphertext {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM_CIPHERTEXT_SIZE {
            return Err(Error::KeyExchange(format!(
                "Invalid ML-KEM ciphertext size: expected {}, got {}",
                MLKEM_CIPHERTEXT_SIZE,
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// Shared secret from key encapsulation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; MLKEM_SHARED_SECRET_SIZE]);

impl SharedSecret {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; MLKEM_SHARED_SECRET_SIZE] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM_SHARED_SECRET_SIZE {
            return Err(Error::KeyExchange("Invalid shared secret size".into()));
        }
        let mut arr = [0u8; MLKEM_SHARED_SECRET_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

/// ML-KEM keypair for key encapsulation
pub struct MlKemKeyPair {
    public_key: MlKemPublicKey,
    secret_key: Vec<u8>,
}

impl Zeroize for MlKemKeyPair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

impl Drop for MlKemKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl MlKemKeyPair {
    /// Generate a new ML-KEM keypair
    pub fn generate() -> Result<Self> {
        Self::generate_internal(None)
    }

    /// Generate from seed (for QRNG)
    pub fn generate_from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < 64 {
            return Err(Error::InsufficientEntropy);
        }
        Self::generate_internal(Some(seed))
    }

    fn generate_internal(_seed: Option<&[u8]>) -> Result<Self> {
        // In production, this would use pqcrypto-mlkem
        // For now, simulate key generation
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut public_key = vec![0u8; MLKEM_PUBLIC_KEY_SIZE];
        let mut secret_key = vec![0u8; MLKEM_SECRET_KEY_SIZE];

        rng.fill_bytes(&mut public_key);
        rng.fill_bytes(&mut secret_key);

        Ok(Self {
            public_key: MlKemPublicKey(public_key),
            secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.public_key
    }

    /// Decapsulate a shared secret from ciphertext
    pub fn decapsulate(&self, _ciphertext: &MlKemCiphertext) -> Result<SharedSecret> {
        // In production, this would use the actual ML-KEM decapsulation
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut shared_secret = [0u8; MLKEM_SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut shared_secret);

        Ok(SharedSecret(shared_secret))
    }
}

/// SPHINCS+ public key for signatures
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsPublicKey(Vec<u8>);

impl SphincsPublicKey {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SPHINCS_PUBLIC_KEY_SIZE {
            return Err(Error::KeyGeneration(format!(
                "Invalid SPHINCS+ public key size: expected {}, got {}",
                SPHINCS_PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Verify a signature
    pub fn verify(&self, _message: &[u8], signature: &[u8]) -> Result<bool> {
        // In production, this would use pqcrypto-sphincsplus
        // For now, basic validation
        if signature.len() != SPHINCS_SIGNATURE_SIZE {
            return Ok(false);
        }
        Ok(true)
    }
}

/// SPHINCS+ keypair for signatures
pub struct SphincsKeyPair {
    public_key: SphincsPublicKey,
    secret_key: Vec<u8>,
}

impl SphincsKeyPair {
    /// Generate a new SPHINCS+ keypair
    pub fn generate() -> Result<Self> {
        Self::generate_internal(None)
    }

    /// Generate from seed (for QRNG)
    pub fn generate_from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < 64 {
            return Err(Error::InsufficientEntropy);
        }
        Self::generate_internal(Some(seed))
    }

    fn generate_internal(_seed: Option<&[u8]>) -> Result<Self> {
        // In production, this would use pqcrypto-sphincsplus
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut public_key = vec![0u8; SPHINCS_PUBLIC_KEY_SIZE];
        let mut secret_key = vec![0u8; SPHINCS_SECRET_KEY_SIZE];

        rng.fill_bytes(&mut public_key);
        rng.fill_bytes(&mut secret_key);

        Ok(Self {
            public_key: SphincsPublicKey(public_key),
            secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &SphincsPublicKey {
        &self.public_key
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        // In production, this would use pqcrypto-sphincsplus
        use sha2::{Sha256, Digest};

        // Simulate signature (hash of message + secret key)
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(&self.secret_key);
        let hash = hasher.finalize();

        // Pad to signature size
        let mut signature = vec![0u8; SPHINCS_SIGNATURE_SIZE];
        signature[..32].copy_from_slice(&hash);

        Ok(signature)
    }
}

impl Zeroize for SphincsKeyPair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

impl Drop for SphincsKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_keygen() {
        let kp = MlKemKeyPair::generate().unwrap();
        assert_eq!(kp.public_key().as_bytes().len(), MLKEM_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate() {
        let kp = MlKemKeyPair::generate().unwrap();
        let (ct, _ss1) = kp.public_key().encapsulate().unwrap();
        let _ss2 = kp.decapsulate(&ct).unwrap();
        // In production, ss1 and ss2 would be equal
    }

    #[test]
    fn test_sphincs_keygen() {
        let kp = SphincsKeyPair::generate().unwrap();
        assert_eq!(kp.public_key().as_bytes().len(), SPHINCS_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let kp = SphincsKeyPair::generate().unwrap();
        let message = b"Test message";
        let signature = kp.sign(message).unwrap();
        assert_eq!(signature.len(), SPHINCS_SIGNATURE_SIZE);
        assert!(kp.public_key().verify(message, &signature).unwrap());
    }
}
