//! SLH-DSA (SPHINCS+) Post-Quantum Signatures for WASM
//!
//! This module provides FIPS 205 SLH-DSA signatures using the pure-Rust fips205 crate.
//! We use SLH-DSA-SHAKE-128s for a balance of security and signature size.
//!
//! Security Level: NIST Level 1 (128-bit classical / 64-bit quantum)
//! Signature size: ~7,856 bytes
//! Public key: 32 bytes
//! Private key: 64 bytes

use crate::crypto::qrng;
use thiserror::Error;
use fips205::slh_dsa_shake_128s;
use fips205::traits::{SerDes, Signer, Verifier};

// Re-export constants
pub const PUBLIC_KEY_LEN: usize = slh_dsa_shake_128s::PK_LEN;
pub const PRIVATE_KEY_LEN: usize = slh_dsa_shake_128s::SK_LEN;
pub const SIGNATURE_LEN: usize = slh_dsa_shake_128s::SIG_LEN;

#[derive(Error, Debug)]
pub enum SlhDsaError {
    #[error("Key generation failed: {0}")]
    KeyGenError(String),
    #[error("Signing failed: {0}")]
    SignError(String),
    #[error("Verification failed: {0}")]
    VerifyError(String),
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),
}

/// SLH-DSA-SHAKE-128s key pair
/// Using the smallest parameter set for reasonable signature sizes in messages
pub struct SlhDsaKeyPair {
    signing_key: slh_dsa_shake_128s::PrivateKey,
    verifying_key: slh_dsa_shake_128s::PublicKey,
}

impl SlhDsaKeyPair {
    /// Generate a new SLH-DSA key pair using QRNG
    pub fn generate() -> Result<Self, SlhDsaError> {
        // Get random seed from QRNG
        let seed = qrng::get_entropy(slh_dsa_shake_128s::SK_LEN)
            .map_err(|e| SlhDsaError::KeyGenError(e.to_string()))?;

        // Create a deterministic RNG from the seed for key generation
        let mut rng = DeterministicRng::new(&seed);

        let (verifying_key, signing_key) = slh_dsa_shake_128s::try_keygen_with_rng(&mut rng)
            .map_err(|_| SlhDsaError::KeyGenError("Key generation failed".to_string()))?;

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create from existing key bytes
    pub fn from_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self, SlhDsaError> {
        if sk_bytes.len() != slh_dsa_shake_128s::SK_LEN {
            return Err(SlhDsaError::InvalidKey(format!(
                "Private key must be {} bytes, got {}",
                slh_dsa_shake_128s::SK_LEN,
                sk_bytes.len()
            )));
        }

        if pk_bytes.len() != slh_dsa_shake_128s::PK_LEN {
            return Err(SlhDsaError::InvalidKey(format!(
                "Public key must be {} bytes, got {}",
                slh_dsa_shake_128s::PK_LEN,
                pk_bytes.len()
            )));
        }

        // Convert slices to fixed-size arrays
        let sk_array: [u8; slh_dsa_shake_128s::SK_LEN] = sk_bytes
            .try_into()
            .map_err(|_| SlhDsaError::InvalidKey("Invalid private key length".to_string()))?;
        let pk_array: [u8; slh_dsa_shake_128s::PK_LEN] = pk_bytes
            .try_into()
            .map_err(|_| SlhDsaError::InvalidKey("Invalid public key length".to_string()))?;

        let signing_key = slh_dsa_shake_128s::PrivateKey::try_from_bytes(&sk_array)
            .map_err(|e| SlhDsaError::InvalidKey(e.to_string()))?;
        let verifying_key = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_array)
            .map_err(|e| SlhDsaError::InvalidKey(e.to_string()))?;

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.clone().into_bytes().to_vec()
    }

    /// Get the private key bytes (for storage)
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.clone().into_bytes().to_vec()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SlhDsaError> {
        let signature = self.signing_key.try_sign(message, &[], false)
            .map_err(|_| SlhDsaError::SignError("Signing failed".to_string()))?;

        Ok(signature.to_vec())
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, SlhDsaError> {
        if signature.len() != slh_dsa_shake_128s::SIG_LEN {
            return Err(SlhDsaError::InvalidSignature(format!(
                "Signature must be {} bytes, got {}",
                slh_dsa_shake_128s::SIG_LEN,
                signature.len()
            )));
        }

        let sig_array: [u8; slh_dsa_shake_128s::SIG_LEN] = signature
            .try_into()
            .map_err(|_| SlhDsaError::InvalidSignature("Invalid signature length".to_string()))?;

        Ok(self.verifying_key.verify(message, &sig_array, &[]))
    }
}

/// Verify a signature with just the public key
pub fn verify_with_public_key(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SlhDsaError> {
    if public_key.len() != slh_dsa_shake_128s::PK_LEN {
        return Err(SlhDsaError::InvalidKey(format!(
            "Public key must be {} bytes, got {}",
            slh_dsa_shake_128s::PK_LEN,
            public_key.len()
        )));
    }

    if signature.len() != slh_dsa_shake_128s::SIG_LEN {
        return Err(SlhDsaError::InvalidSignature(format!(
            "Signature must be {} bytes, got {}",
            slh_dsa_shake_128s::SIG_LEN,
            signature.len()
        )));
    }

    let pk_array: [u8; slh_dsa_shake_128s::PK_LEN] = public_key
        .try_into()
        .map_err(|_| SlhDsaError::InvalidKey("Invalid public key length".to_string()))?;

    let verifying_key = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_array)
        .map_err(|e| SlhDsaError::InvalidKey(e.to_string()))?;

    let sig_array: [u8; slh_dsa_shake_128s::SIG_LEN] = signature
        .try_into()
        .map_err(|_| SlhDsaError::InvalidSignature("Invalid signature length".to_string()))?;

    Ok(verifying_key.verify(message, &sig_array, &[]))
}

/// Constants for SLH-DSA-SHAKE-128s
pub mod constants {
    use super::*;
    pub const PUBLIC_KEY_LEN: usize = slh_dsa_shake_128s::PK_LEN;
    pub const PRIVATE_KEY_LEN: usize = slh_dsa_shake_128s::SK_LEN;
    pub const SIGNATURE_LEN: usize = slh_dsa_shake_128s::SIG_LEN;
}

/// Deterministic RNG for key generation from seed
struct DeterministicRng {
    state: [u8; 32],
    counter: u64,
}

impl DeterministicRng {
    fn new(seed: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let hash = hasher.finalize();
        let mut state = [0u8; 32];
        state.copy_from_slice(&hash);
        Self { state, counter: 0 }
    }
}

impl rand::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use sha2::{Sha256, Digest};

        let mut offset = 0;
        while offset < dest.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.state);
            hasher.update(&self.counter.to_le_bytes());
            let hash = hasher.finalize();

            let to_copy = std::cmp::min(32, dest.len() - offset);
            dest[offset..offset + to_copy].copy_from_slice(&hash[..to_copy]);

            offset += to_copy;
            self.counter += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand::CryptoRng for DeterministicRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify() {
        let keypair = SlhDsaKeyPair::generate().unwrap();
        let message = b"Hello, post-quantum world!";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).unwrap());

        // Verify with wrong message fails
        let wrong_message = b"Wrong message";
        assert!(!keypair.verify(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_verify_with_public_key() {
        let keypair = SlhDsaKeyPair::generate().unwrap();
        let message = b"Test message for verification";

        let signature = keypair.sign(message).unwrap();
        let public_key = keypair.public_key_bytes();

        assert!(verify_with_public_key(&public_key, message, &signature).unwrap());
    }

    #[test]
    fn test_key_serialization() {
        let keypair = SlhDsaKeyPair::generate().unwrap();
        let pk_bytes = keypair.public_key_bytes();
        let sk_bytes = keypair.private_key_bytes();

        let restored = SlhDsaKeyPair::from_bytes(&sk_bytes, &pk_bytes).unwrap();

        let message = b"Serialization test";
        let sig1 = keypair.sign(message).unwrap();

        // Restored keypair should verify original signature
        assert!(restored.verify(message, &sig1).unwrap());
    }
}
