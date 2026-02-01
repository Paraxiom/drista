//! WASM-compatible post-quantum cryptographic primitives
//!
//! Uses ml-kem (pure Rust) instead of pqcrypto-mlkem (C bindings)
//! for WebAssembly compatibility.

use crate::{Error, Result};
use ml_kem::MlKem1024Params;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem};
use ml_kem::{KemCore, EncodedSizeUser};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Type alias for ML-KEM-1024
type MlKem = Kem<MlKem1024Params>;

/// Size of ML-KEM-1024 shared secret
const SHARED_SECRET_SIZE: usize = 32;

// ML-KEM-1024 sizes
const EK_SIZE: usize = 1568;  // Encapsulation key size
const DK_SIZE: usize = 3168;  // Decapsulation key size
const CT_SIZE: usize = 1568;  // Ciphertext size

/// ML-KEM public key (encapsulation key) for key encapsulation
#[derive(Clone, Serialize, Deserialize)]
pub struct MlKemPublicKey(Vec<u8>);

impl MlKemPublicKey {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != EK_SIZE {
            return Err(Error::KeyGeneration(format!(
                "Invalid ML-KEM public key size: expected {}, got {}",
                EK_SIZE, bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Encapsulate a shared secret
    pub fn encapsulate(&self) -> Result<(MlKemCiphertext, SharedSecret)> {
        // Parse encapsulation key from bytes
        let ek_array: [u8; EK_SIZE] = self.0.as_slice().try_into()
            .map_err(|_| Error::KeyExchange("Invalid encapsulation key size".into()))?;

        let ek = EncapsulationKey::<MlKem1024Params>::from_bytes(&ek_array.into());

        let (ct, ss) = ek.encapsulate(&mut rand::thread_rng())
            .map_err(|_| Error::KeyExchange("Encapsulation failed".into()))?;

        let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(ss.as_slice());

        Ok((
            MlKemCiphertext(ct.as_slice().to_vec()),
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
        if bytes.len() != CT_SIZE {
            return Err(Error::KeyExchange(format!(
                "Invalid ML-KEM ciphertext size: expected {}, got {}",
                CT_SIZE, bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// Shared secret from key encapsulation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_SIZE]);

impl SharedSecret {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SHARED_SECRET_SIZE {
            return Err(Error::KeyExchange("Invalid shared secret size".into()));
        }
        let mut arr = [0u8; SHARED_SECRET_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

/// ML-KEM keypair for key encapsulation (WASM-compatible)
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
        let (dk, ek) = MlKem::generate(&mut rand::thread_rng());

        Ok(Self {
            public_key: MlKemPublicKey(ek.as_bytes().to_vec()),
            secret_key: dk.as_bytes().to_vec(),
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.public_key
    }

    /// Decapsulate a shared secret from ciphertext
    pub fn decapsulate(&self, ciphertext: &MlKemCiphertext) -> Result<SharedSecret> {
        // Parse decapsulation key
        let dk_array: [u8; DK_SIZE] = self.secret_key.as_slice().try_into()
            .map_err(|_| Error::KeyExchange("Invalid decapsulation key size".into()))?;

        let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(&dk_array.into());

        // Parse ciphertext
        let ct_array: [u8; CT_SIZE] = ciphertext.as_bytes().try_into()
            .map_err(|_| Error::KeyExchange("Invalid ciphertext size".into()))?;

        // Ciphertext type wraps Kem<Params>
        let ct: ml_kem::Ciphertext<MlKem> = ct_array.into();

        let ss = dk.decapsulate(&ct)
            .map_err(|_| Error::KeyExchange("Decapsulation failed".into()))?;

        let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(ss.as_slice());

        Ok(SharedSecret(shared_secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_keygen() {
        let kp = MlKemKeyPair::generate().unwrap();
        assert_eq!(kp.public_key().as_bytes().len(), EK_SIZE);
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate() {
        let kp = MlKemKeyPair::generate().unwrap();
        let (ct, ss1) = kp.public_key().encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
