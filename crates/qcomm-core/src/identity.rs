//! Identity management for Quantum Communicator
//!
//! Identities are derived from SPHINCS+ signing keys, providing
//! post-quantum secure authentication and fingerprinting.

use crate::crypto::pq::{SphincsKeyPair, SphincsPublicKey};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

/// A cryptographic fingerprint derived from the public key
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; 8]);

impl Fingerprint {
    /// Create a fingerprint from a SPHINCS+ public key
    pub fn from_public_key(pubkey: &SphincsPublicKey) -> Self {
        let hash = Sha256::digest(pubkey.as_bytes());
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&hash[..8]);
        Self(fp)
    }

    /// Get the fingerprint bytes
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Display as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        if bytes.len() != 8 {
            return Err(Error::Serialization("Invalid fingerprint length".into()));
        }
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&bytes);
        Ok(Self(fp))
    }

    /// Generate an identicon seed from this fingerprint
    pub fn identicon_seed(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A user's identity in Quantum Communicator
#[derive(Serialize, Deserialize)]
pub struct Identity {
    /// SPHINCS+ signing keypair
    #[serde(skip)]
    signing_keypair: Option<SphincsKeyPair>,

    /// Public key for verification
    public_key: SphincsPublicKey,

    /// Cached fingerprint
    fingerprint: Fingerprint,

    /// Optional display name
    display_name: Option<String>,
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Result<Self> {
        let signing_keypair = SphincsKeyPair::generate()?;
        let public_key = signing_keypair.public_key().clone();
        let fingerprint = Fingerprint::from_public_key(&public_key);

        Ok(Self {
            signing_keypair: Some(signing_keypair),
            public_key,
            fingerprint,
            display_name: None,
        })
    }

    /// Generate identity using QRNG entropy
    #[cfg(feature = "qrng")]
    pub fn generate_with_qrng() -> Result<Self> {
        use crate::crypto::qrng;

        let entropy = qrng::get_entropy(64)?;
        let signing_keypair = SphincsKeyPair::generate_from_seed(&entropy)?;
        let public_key = signing_keypair.public_key().clone();
        let fingerprint = Fingerprint::from_public_key(&public_key);

        Ok(Self {
            signing_keypair: Some(signing_keypair),
            public_key,
            fingerprint,
            display_name: None,
        })
    }

    /// Create identity from existing keypair
    pub fn from_keypair(keypair: SphincsKeyPair) -> Self {
        let public_key = keypair.public_key().clone();
        let fingerprint = Fingerprint::from_public_key(&public_key);

        Self {
            signing_keypair: Some(keypair),
            public_key,
            fingerprint,
            display_name: None,
        }
    }

    /// Create a public-only identity (for representing peers)
    pub fn from_public_key(public_key: SphincsPublicKey) -> Self {
        let fingerprint = Fingerprint::from_public_key(&public_key);

        Self {
            signing_keypair: None,
            public_key,
            fingerprint,
            display_name: None,
        }
    }

    /// Get the fingerprint
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Get the public key
    pub fn public_key(&self) -> &SphincsPublicKey {
        &self.public_key
    }

    /// Check if this identity has signing capability
    pub fn can_sign(&self) -> bool {
        self.signing_keypair.is_some()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let keypair = self.signing_keypair.as_ref()
            .ok_or_else(|| Error::KeyGeneration("No signing key available".into()))?;
        keypair.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.public_key.verify(message, signature)
    }

    /// Set display name
    pub fn set_display_name(&mut self, name: impl Into<String>) {
        self.display_name = Some(name.into());
    }

    /// Get display name or fingerprint as fallback
    pub fn display_name(&self) -> &str {
        self.display_name.as_deref()
            .unwrap_or_else(|| Box::leak(self.fingerprint.to_hex().into_boxed_str()))
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // Zeroize sensitive data
        if let Some(ref mut kp) = self.signing_keypair {
            kp.zeroize();
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint)
            .field("display_name", &self.display_name)
            .field("can_sign", &self.can_sign())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate().unwrap();
        assert!(identity.can_sign());
        assert_eq!(identity.fingerprint().as_bytes().len(), 8);
    }

    #[test]
    fn test_sign_verify() {
        let identity = Identity::generate().unwrap();
        let message = b"Hello, Quantum World!";

        let signature = identity.sign(message).unwrap();
        assert!(identity.verify(message, &signature).unwrap());

        // Tampered message should fail
        let tampered = b"Hello, Classical World!";
        assert!(!identity.verify(tampered, &signature).unwrap_or(true));
    }

    #[test]
    fn test_fingerprint_roundtrip() {
        let identity = Identity::generate().unwrap();
        let hex = identity.fingerprint().to_hex();
        let parsed = Fingerprint::from_hex(&hex).unwrap();
        assert_eq!(identity.fingerprint(), &parsed);
    }
}
