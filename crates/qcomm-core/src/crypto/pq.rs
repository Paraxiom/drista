//! Post-quantum cryptographic primitives
//!
//! Provides ML-KEM (Kyber) for key encapsulation and SPHINCS+ for signatures.
//! Uses NIST standardized algorithms via pqcrypto crate.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Use the real pqcrypto libraries
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_sphincsplus::sphincssha2256fsimple as sphincs;
// Import traits to bring methods into scope
use pqcrypto_traits::kem::Ciphertext as PqCtTrait;
use pqcrypto_traits::kem::PublicKey as PqKemPkTrait;
use pqcrypto_traits::kem::SecretKey as PqKemSkTrait;
use pqcrypto_traits::kem::SharedSecret as PqSsTrait;
use pqcrypto_traits::sign::DetachedSignature as PqDetSigTrait;
use pqcrypto_traits::sign::PublicKey as PqSignPkTrait;
use pqcrypto_traits::sign::SecretKey as PqSignSkTrait;

// ML-KEM-1024 parameters (NIST Level 5)
const MLKEM_PUBLIC_KEY_SIZE: usize = mlkem1024::public_key_bytes();
const MLKEM_SECRET_KEY_SIZE: usize = mlkem1024::secret_key_bytes();
const MLKEM_CIPHERTEXT_SIZE: usize = mlkem1024::ciphertext_bytes();
const MLKEM_SHARED_SECRET_SIZE: usize = mlkem1024::shared_secret_bytes();

// SPHINCS+-SHA2-256f-simple parameters
const SPHINCS_PUBLIC_KEY_SIZE: usize = sphincs::public_key_bytes();
const SPHINCS_SECRET_KEY_SIZE: usize = sphincs::secret_key_bytes();
const SPHINCS_SIGNATURE_SIZE: usize = sphincs::signature_bytes();

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
        let pk = PqKemPkTrait::from_bytes(&self.0)
            .map_err(|_| Error::KeyExchange("Invalid ML-KEM public key".into()))?;

        let (ss, ct) = mlkem1024::encapsulate(&pk);

        let mut shared_secret = [0u8; MLKEM_SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(PqSsTrait::as_bytes(&ss));

        Ok((
            MlKemCiphertext(PqCtTrait::as_bytes(&ct).to_vec()),
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
        let (pk, sk) = mlkem1024::keypair();

        Ok(Self {
            public_key: MlKemPublicKey(PqKemPkTrait::as_bytes(&pk).to_vec()),
            secret_key: PqKemSkTrait::as_bytes(&sk).to_vec(),
        })
    }

    /// Generate from seed (for QRNG)
    pub fn generate_from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < 64 {
            return Err(Error::InsufficientEntropy);
        }
        // For seeded generation, we'd need a deterministic variant
        // For now, fall back to random generation
        // TODO: Implement deterministic keygen when pqcrypto supports it
        Self::generate()
    }

    /// Get the public key
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.public_key
    }

    /// Decapsulate a shared secret from ciphertext
    pub fn decapsulate(&self, ciphertext: &MlKemCiphertext) -> Result<SharedSecret> {
        let sk: mlkem1024::SecretKey = PqKemSkTrait::from_bytes(&self.secret_key)
            .map_err(|_| Error::KeyExchange("Invalid ML-KEM secret key".into()))?;

        let ct: mlkem1024::Ciphertext = PqCtTrait::from_bytes(ciphertext.as_bytes())
            .map_err(|_| Error::KeyExchange("Invalid ML-KEM ciphertext".into()))?;

        let ss = mlkem1024::decapsulate(&ct, &sk);

        let mut shared_secret = [0u8; MLKEM_SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(PqSsTrait::as_bytes(&ss));

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

    /// Verify a detached signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != SPHINCS_SIGNATURE_SIZE {
            return Ok(false);
        }

        let pk: sphincs::PublicKey = PqSignPkTrait::from_bytes(&self.0)
            .map_err(|_| Error::SignatureVerification("Invalid SPHINCS+ public key".into()))?;

        let sig: sphincs::DetachedSignature = PqDetSigTrait::from_bytes(signature)
            .map_err(|_| Error::SignatureVerification("Invalid SPHINCS+ signature".into()))?;

        match sphincs::verify_detached_signature(&sig, message, &pk) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
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
        let (pk, sk) = sphincs::keypair();

        Ok(Self {
            public_key: SphincsPublicKey(PqSignPkTrait::as_bytes(&pk).to_vec()),
            secret_key: PqSignSkTrait::as_bytes(&sk).to_vec(),
        })
    }

    /// Generate from seed (for QRNG)
    pub fn generate_from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < 64 {
            return Err(Error::InsufficientEntropy);
        }
        // TODO: Implement deterministic keygen when pqcrypto supports it
        Self::generate()
    }

    /// Get the public key
    pub fn public_key(&self) -> &SphincsPublicKey {
        &self.public_key
    }

    /// Sign a message (detached signature)
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = PqSignSkTrait::from_bytes(&self.secret_key)
            .map_err(|_| Error::SignatureCreation("Invalid SPHINCS+ secret key".into()))?;

        let sig = sphincs::detached_sign(message, &sk);

        Ok(PqDetSigTrait::as_bytes(&sig).to_vec())
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
        let (ct, ss1) = kp.public_key().encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_sphincs_keygen() {
        let kp = SphincsKeyPair::generate().unwrap();
        assert_eq!(kp.public_key().as_bytes().len(), SPHINCS_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let kp = SphincsKeyPair::generate().unwrap();
        let message = b"Test message for SPHINCS+ signature";
        let signature = kp.sign(message).unwrap();
        assert_eq!(signature.len(), SPHINCS_SIGNATURE_SIZE);
        assert!(kp.public_key().verify(message, &signature).unwrap());
    }

    #[test]
    fn test_sphincs_verify_wrong_message() {
        let kp = SphincsKeyPair::generate().unwrap();
        let message = b"Original message";
        let signature = kp.sign(message).unwrap();
        let wrong_message = b"Wrong message";
        assert!(!kp.public_key().verify(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_ratchet_integration() {
        // Simulate initial key exchange
        let bob_keypair = MlKemKeyPair::generate().unwrap();
        let (ct, alice_ss) = bob_keypair.public_key().encapsulate().unwrap();
        let bob_ss = bob_keypair.decapsulate(&ct).unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(alice_ss.as_bytes(), bob_ss.as_bytes());
    }
}
