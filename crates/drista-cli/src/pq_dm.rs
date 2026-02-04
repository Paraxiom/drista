//! Post-Quantum Direct Messages (Kind 20004)
//!
//! Implements ML-KEM-1024 + AES-256-GCM encryption for Nostr DMs.
//! Compatible with the web app's pq-crypto.js format.
//!
//! Message Format:
//! - New session: `pq1:init:<ourPubKey>:<keyCiphertext>:<nonce>:<ciphertext>`
//! - Regular msg: `pq1:msg:<nonce>:<ciphertext>` (requires established session)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use qcomm_core::crypto::{MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, SharedSecret};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::RwLock;

/// PQ-DM Nostr event kind
pub const KIND_PQ_ENCRYPTED_DM: u16 = 20004;

/// PQ public key publication kind (for discovery)
pub const KIND_PQ_PUBKEY: u16 = 30078;

/// Session manager for PQ-DM
pub struct PqSessionManager {
    /// Our ML-KEM keypair
    keypair: MlKemKeyPair,
    /// Cached peer public keys (Nostr pubkey -> ML-KEM pubkey)
    peer_keys: RwLock<HashMap<String, MlKemPublicKey>>,
    /// Active session keys (Nostr pubkey -> AES key)
    session_keys: RwLock<HashMap<String, [u8; 32]>>,
}

impl PqSessionManager {
    /// Create a new PQ session manager
    pub fn new() -> Result<Self> {
        let keypair = MlKemKeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate ML-KEM keypair: {}", e))?;

        Ok(Self {
            keypair,
            peer_keys: RwLock::new(HashMap::new()),
            session_keys: RwLock::new(HashMap::new()),
        })
    }

    /// Get our PQ public key as base64
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.keypair.public_key().as_bytes())
    }

    /// Register a peer's PQ public key
    pub fn register_peer_key(&self, nostr_pubkey: &str, pq_pubkey_base64: &str) -> Result<()> {
        let pq_pubkey_bytes = BASE64.decode(pq_pubkey_base64)?;
        let pq_pubkey = MlKemPublicKey::from_bytes(&pq_pubkey_bytes)
            .map_err(|e| anyhow!("Invalid ML-KEM public key: {}", e))?;

        self.peer_keys
            .write()
            .unwrap()
            .insert(nostr_pubkey.to_string(), pq_pubkey);

        Ok(())
    }

    /// Check if we have a peer's PQ public key
    pub fn has_peer_key(&self, nostr_pubkey: &str) -> bool {
        self.peer_keys.read().unwrap().contains_key(nostr_pubkey)
    }

    /// Encrypt a message for a peer using PQ-DM
    ///
    /// Returns the encrypted content in the format:
    /// `pq1:init:<ourPubKey>:<keyCiphertext>:<nonce>:<ciphertext>`
    pub fn encrypt(&self, recipient_nostr_pubkey: &str, plaintext: &str) -> Result<String> {
        let peer_keys = self.peer_keys.read().unwrap();
        let recipient_pq_key = peer_keys
            .get(recipient_nostr_pubkey)
            .ok_or_else(|| anyhow!("No PQ public key for recipient. Register it first."))?;

        // Encapsulate shared secret to recipient's public key
        let (ciphertext, shared_secret) = recipient_pq_key
            .encapsulate()
            .map_err(|e| anyhow!("ML-KEM encapsulation failed: {}", e))?;

        // Derive AES key from shared secret using HKDF
        let aes_key = derive_aes_key(shared_secret.as_bytes(), b"pq-dm-v1")?;

        // Generate random nonce for AES-GCM
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&aes_key)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("AES-GCM encryption failed: {}", e))?;

        // Format: pq1:init:<ourPubKey>:<keyCiphertext>:<nonce>:<ciphertext>
        Ok(format!(
            "pq1:init:{}:{}:{}:{}",
            self.public_key_base64(),
            BASE64.encode(ciphertext.as_bytes()),
            BASE64.encode(&nonce_bytes),
            BASE64.encode(&encrypted)
        ))
    }

    /// Decrypt a PQ-DM message
    pub fn decrypt(&self, sender_nostr_pubkey: &str, content: &str) -> Result<String> {
        if !content.starts_with("pq1:") {
            return Err(anyhow!("Not a PQ-encrypted message"));
        }

        let parts: Vec<&str> = content.split(':').collect();
        let msg_type = parts.get(1).ok_or_else(|| anyhow!("Invalid PQ message format"))?;

        match *msg_type {
            "init" => {
                // pq1:init:<theirPubKey>:<keyCiphertext>:<nonce>:<ciphertext>
                if parts.len() != 6 {
                    return Err(anyhow!(
                        "Invalid init message format: expected 6 parts, got {}",
                        parts.len()
                    ));
                }

                let their_pubkey_b64 = parts[2];
                let key_ciphertext_b64 = parts[3];
                let nonce_b64 = parts[4];
                let ciphertext_b64 = parts[5];

                // Register their public key for future messages
                self.register_peer_key(sender_nostr_pubkey, their_pubkey_b64)?;

                // Decapsulate to get shared secret
                let key_ciphertext_bytes = BASE64.decode(key_ciphertext_b64)?;
                let key_ciphertext = MlKemCiphertext::from_bytes(&key_ciphertext_bytes)
                    .map_err(|e| anyhow!("Invalid ML-KEM ciphertext: {}", e))?;

                let shared_secret = self
                    .keypair
                    .decapsulate(&key_ciphertext)
                    .map_err(|e| anyhow!("ML-KEM decapsulation failed: {}", e))?;

                // Derive AES key
                let aes_key = derive_aes_key(shared_secret.as_bytes(), b"pq-dm-v1")?;

                // Store session key for future messages
                self.session_keys
                    .write()
                    .unwrap()
                    .insert(sender_nostr_pubkey.to_string(), aes_key);

                // Decrypt message
                let nonce_bytes = BASE64.decode(nonce_b64)?;
                let ciphertext = BASE64.decode(ciphertext_b64)?;

                let cipher = Aes256Gcm::new_from_slice(&aes_key)?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                let plaintext = cipher
                    .decrypt(nonce, ciphertext.as_ref())
                    .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))?;

                Ok(String::from_utf8(plaintext)?)
            }
            "msg" => {
                // pq1:msg:<nonce>:<ciphertext>
                // Requires established session
                if parts.len() != 4 {
                    return Err(anyhow!(
                        "Invalid msg format: expected 4 parts, got {}",
                        parts.len()
                    ));
                }

                let nonce_b64 = parts[2];
                let ciphertext_b64 = parts[3];

                // Get session key
                let session_keys = self.session_keys.read().unwrap();
                let aes_key = session_keys
                    .get(sender_nostr_pubkey)
                    .ok_or_else(|| anyhow!("No session established. Need init message first."))?;

                // Decrypt
                let nonce_bytes = BASE64.decode(nonce_b64)?;
                let ciphertext = BASE64.decode(ciphertext_b64)?;

                let cipher = Aes256Gcm::new_from_slice(aes_key)?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                let plaintext = cipher
                    .decrypt(nonce, ciphertext.as_ref())
                    .map_err(|e| anyhow!("AES-GCM decryption failed: {}", e))?;

                Ok(String::from_utf8(plaintext)?)
            }
            _ => Err(anyhow!("Unknown PQ message type: {}", msg_type)),
        }
    }
}

/// Derive AES-256 key from shared secret using HKDF-SHA256
fn derive_aes_key(shared_secret: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| anyhow!("HKDF expansion failed: {}", e))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_dm_roundtrip() {
        // Alice and Bob each have their own session managers
        let alice = PqSessionManager::new().unwrap();
        let bob = PqSessionManager::new().unwrap();

        // Exchange public keys
        alice
            .register_peer_key("bob_nostr_pk", &bob.public_key_base64())
            .unwrap();
        bob.register_peer_key("alice_nostr_pk", &alice.public_key_base64())
            .unwrap();

        // Alice encrypts a message to Bob
        let plaintext = "Hello Bob, this is a PQ-encrypted message!";
        let encrypted = alice.encrypt("bob_nostr_pk", plaintext).unwrap();

        assert!(encrypted.starts_with("pq1:init:"));

        // Bob decrypts
        let decrypted = bob.decrypt("alice_nostr_pk", &encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_pq_dm_unicode() {
        let alice = PqSessionManager::new().unwrap();
        let bob = PqSessionManager::new().unwrap();

        alice
            .register_peer_key("bob", &bob.public_key_base64())
            .unwrap();

        let plaintext = "Hello 你好 🎉 Post-Quantum!";
        let encrypted = alice.encrypt("bob", plaintext).unwrap();
        let decrypted = bob.decrypt("alice", &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_public_key_format() {
        let manager = PqSessionManager::new().unwrap();
        let pubkey = manager.public_key_base64();

        // ML-KEM-1024 public key is 1568 bytes, base64 encoded
        let decoded = BASE64.decode(&pubkey).unwrap();
        assert_eq!(decoded.len(), 1568);
    }
}
