//! PQ-Triple-Ratchet Protocol
//!
//! A post-quantum secure double ratchet variant using:
//! - ML-KEM for key encapsulation (replaces X25519 DH)
//! - SPHINCS+ for authentication
//! - AES-256-GCM for symmetric encryption
//! - HKDF-SHA256 for key derivation
//!
//! The "triple" ratchet refers to three ratchet chains:
//! 1. Root chain (ML-KEM ratchet)
//! 2. Sending chain (symmetric ratchet)
//! 3. Receiving chain (symmetric ratchet)

use crate::crypto::pq::{MlKemKeyPair, MlKemPublicKey, MlKemCiphertext, SharedSecret};
use crate::crypto::aead;
use crate::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of chain keys
const CHAIN_KEY_SIZE: usize = 32;

/// Size of message keys
const MESSAGE_KEY_SIZE: usize = 32;

/// Maximum number of skipped message keys to store
const MAX_SKIP: usize = 1000;

/// Info string for root key derivation
const ROOT_INFO: &[u8] = b"QuantumCommunicator_RootChain_v1";

/// Info string for chain key derivation
const CHAIN_INFO: &[u8] = b"QuantumCommunicator_ChainKey_v1";

/// Info string for message key derivation
const MESSAGE_INFO: &[u8] = b"QuantumCommunicator_MessageKey_v1";

/// A chain key in the ratchet
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct ChainKey([u8; CHAIN_KEY_SIZE]);

impl ChainKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CHAIN_KEY_SIZE {
            return Err(Error::RatchetCorrupted("Invalid chain key size".into()));
        }
        let mut arr = [0u8; CHAIN_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A message key for encryption/decryption
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct MessageKey([u8; MESSAGE_KEY_SIZE]);

impl MessageKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// State of one ratchet chain (sending or receiving)
#[derive(Clone)]
struct ChainState {
    chain_key: ChainKey,
    counter: u32,
}

impl ChainState {
    fn new(chain_key: ChainKey) -> Self {
        Self {
            chain_key,
            counter: 0,
        }
    }

    /// Advance the chain and derive a message key
    fn advance(&mut self) -> Result<MessageKey> {
        let hk = Hkdf::<Sha256>::new(None, self.chain_key.as_bytes());

        // Derive next chain key
        let mut next_chain_key = [0u8; CHAIN_KEY_SIZE];
        hk.expand(CHAIN_INFO, &mut next_chain_key)
            .map_err(|_| Error::RatchetCorrupted("Chain key derivation failed".into()))?;

        // Derive message key
        let mut message_key = [0u8; MESSAGE_KEY_SIZE];
        hk.expand(MESSAGE_INFO, &mut message_key)
            .map_err(|_| Error::RatchetCorrupted("Message key derivation failed".into()))?;

        self.chain_key = ChainKey(next_chain_key);
        self.counter += 1;

        Ok(MessageKey(message_key))
    }
}

impl Zeroize for ChainState {
    fn zeroize(&mut self) {
        self.chain_key.zeroize();
    }
}

/// Header for ratchet messages
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// ML-KEM public key for this message
    pub kem_public_key: Vec<u8>,
    /// Previous chain length
    pub previous_chain_length: u32,
    /// Message number in current chain
    pub message_number: u32,
}

/// A skipped message key entry
#[derive(Clone)]
struct SkippedKey {
    kem_public_key: Vec<u8>,
    message_number: u32,
    message_key: MessageKey,
}

impl Zeroize for SkippedKey {
    fn zeroize(&mut self) {
        self.message_key.zeroize();
    }
}

/// PQ-Triple-Ratchet session state
pub struct PqTripleRatchet {
    /// Our current ML-KEM keypair
    our_keypair: MlKemKeyPair,

    /// Their current ML-KEM public key
    their_public_key: Option<MlKemPublicKey>,

    /// Root key
    root_key: ChainKey,

    /// Sending chain state
    sending_chain: Option<ChainState>,

    /// Receiving chain state
    receiving_chain: Option<ChainState>,

    /// Previous sending chain length
    previous_sending_length: u32,

    /// Skipped message keys
    skipped_keys: Vec<SkippedKey>,
}

impl PqTripleRatchet {
    /// Initialize as the session initiator (Alice)
    pub fn init_initiator(
        shared_secret: SharedSecret,
        their_public_key: MlKemPublicKey,
    ) -> Result<Self> {
        let our_keypair = MlKemKeyPair::generate()?;

        // Derive initial root and sending chain keys
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

        let mut root_key = [0u8; CHAIN_KEY_SIZE];
        hk.expand(ROOT_INFO, &mut root_key)
            .map_err(|_| Error::RatchetCorrupted("Root key derivation failed".into()))?;

        let mut sending_chain_key = [0u8; CHAIN_KEY_SIZE];
        hk.expand(CHAIN_INFO, &mut sending_chain_key)
            .map_err(|_| Error::RatchetCorrupted("Chain key derivation failed".into()))?;

        Ok(Self {
            our_keypair,
            their_public_key: Some(their_public_key),
            root_key: ChainKey(root_key),
            sending_chain: Some(ChainState::new(ChainKey(sending_chain_key))),
            receiving_chain: None,
            previous_sending_length: 0,
            skipped_keys: Vec::new(),
        })
    }

    /// Initialize as the session responder (Bob)
    pub fn init_responder(
        shared_secret: SharedSecret,
        our_keypair: MlKemKeyPair,
    ) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

        let mut root_key = [0u8; CHAIN_KEY_SIZE];
        hk.expand(ROOT_INFO, &mut root_key)
            .map_err(|_| Error::RatchetCorrupted("Root key derivation failed".into()))?;

        // Derive initial receiving chain key (matches initiator's sending chain)
        let mut receiving_chain_key = [0u8; CHAIN_KEY_SIZE];
        hk.expand(CHAIN_INFO, &mut receiving_chain_key)
            .map_err(|_| Error::RatchetCorrupted("Chain key derivation failed".into()))?;

        Ok(Self {
            our_keypair,
            their_public_key: None,
            root_key: ChainKey(root_key),
            sending_chain: None,
            receiving_chain: Some(ChainState::new(ChainKey(receiving_chain_key))),
            previous_sending_length: 0,
            skipped_keys: Vec::new(),
        })
    }

    /// Get our current public key
    pub fn our_public_key(&self) -> &MlKemPublicKey {
        self.our_keypair.public_key()
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>)> {
        // Ensure we have a sending chain
        if self.sending_chain.is_none() {
            return Err(Error::RatchetCorrupted("No sending chain established".into()));
        }

        let chain = self.sending_chain.as_mut().unwrap();
        let message_key = chain.advance()?;

        let header = RatchetHeader {
            kem_public_key: self.our_keypair.public_key().as_bytes().to_vec(),
            previous_chain_length: self.previous_sending_length,
            message_number: chain.counter - 1,
        };

        // Encrypt with AEAD
        let ad = bincode::serialize(&header)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let ciphertext = aead::encrypt(plaintext, message_key.as_bytes(), &ad)?;

        Ok((header, ciphertext))
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, header: &RatchetHeader, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Try skipped keys first
        if let Some(plaintext) = self.try_skipped_keys(header, ciphertext)? {
            return Ok(plaintext);
        }

        // Check if we need to do a DH ratchet step
        let their_pk = MlKemPublicKey::from_bytes(&header.kem_public_key)?;
        let their_pk_changed = self.their_public_key.as_ref()
            .map(|pk| pk.as_bytes() != their_pk.as_bytes())
            .unwrap_or(false); // Changed: false if None (first message case)

        // Special case: first message received (their_public_key is None)
        // In this case, we just set their key but don't do a full ratchet
        // because the responder's receiving chain was initialized from the shared secret
        let is_first_message = self.their_public_key.is_none();

        if is_first_message {
            // First message: just record their public key, don't ratchet
            self.their_public_key = Some(their_pk);
        } else if their_pk_changed {
            // Skip any remaining messages in current receiving chain
            self.skip_messages(header.previous_chain_length)?;

            // DH ratchet step
            self.dh_ratchet(their_pk)?;
        }

        // Skip messages if needed
        self.skip_messages(header.message_number)?;

        // Decrypt with current receiving chain
        let chain = self.receiving_chain.as_mut()
            .ok_or_else(|| Error::RatchetCorrupted("No receiving chain".into()))?;

        let message_key = chain.advance()?;

        let ad = bincode::serialize(header)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        aead::decrypt(ciphertext, message_key.as_bytes(), &ad)
    }

    /// Perform a DH ratchet step (actually KEM ratchet in PQ version)
    fn dh_ratchet(&mut self, their_public_key: MlKemPublicKey) -> Result<()> {
        // Save previous sending chain length
        if let Some(ref chain) = self.sending_chain {
            self.previous_sending_length = chain.counter;
        }

        self.their_public_key = Some(their_public_key.clone());

        // Derive receiving chain from their public key
        let (_, shared_secret) = their_public_key.encapsulate()?;
        let hk = Hkdf::<Sha256>::new(Some(self.root_key.as_bytes()), shared_secret.as_bytes());

        let mut new_root_key = [0u8; CHAIN_KEY_SIZE];
        let mut receiving_chain_key = [0u8; CHAIN_KEY_SIZE];

        hk.expand(ROOT_INFO, &mut new_root_key)
            .map_err(|_| Error::RatchetCorrupted("Root key derivation failed".into()))?;
        hk.expand(CHAIN_INFO, &mut receiving_chain_key)
            .map_err(|_| Error::RatchetCorrupted("Chain key derivation failed".into()))?;

        self.root_key = ChainKey(new_root_key);
        self.receiving_chain = Some(ChainState::new(ChainKey(receiving_chain_key)));

        // Generate new keypair and derive sending chain
        self.our_keypair = MlKemKeyPair::generate()?;
        let (_, shared_secret) = self.their_public_key.as_ref().unwrap().encapsulate()?;
        let hk = Hkdf::<Sha256>::new(Some(self.root_key.as_bytes()), shared_secret.as_bytes());

        let mut new_root_key = [0u8; CHAIN_KEY_SIZE];
        let mut sending_chain_key = [0u8; CHAIN_KEY_SIZE];

        hk.expand(ROOT_INFO, &mut new_root_key)
            .map_err(|_| Error::RatchetCorrupted("Root key derivation failed".into()))?;
        hk.expand(CHAIN_INFO, &mut sending_chain_key)
            .map_err(|_| Error::RatchetCorrupted("Chain key derivation failed".into()))?;

        self.root_key = ChainKey(new_root_key);
        self.sending_chain = Some(ChainState::new(ChainKey(sending_chain_key)));

        Ok(())
    }

    /// Skip messages and store their keys
    fn skip_messages(&mut self, until: u32) -> Result<()> {
        let chain = match self.receiving_chain.as_mut() {
            Some(c) => c,
            None => return Ok(()),
        };

        let their_pk = self.their_public_key.as_ref()
            .ok_or_else(|| Error::RatchetCorrupted("No their public key".into()))?;

        while chain.counter < until {
            if self.skipped_keys.len() >= MAX_SKIP {
                return Err(Error::RatchetCorrupted("Too many skipped messages".into()));
            }

            let message_key = chain.advance()?;
            self.skipped_keys.push(SkippedKey {
                kem_public_key: their_pk.as_bytes().to_vec(),
                message_number: chain.counter - 1,
                message_key,
            });
        }

        Ok(())
    }

    /// Try to decrypt with skipped keys
    fn try_skipped_keys(&mut self, header: &RatchetHeader, ciphertext: &[u8]) -> Result<Option<Vec<u8>>> {
        let idx = self.skipped_keys.iter().position(|sk| {
            sk.kem_public_key == header.kem_public_key && sk.message_number == header.message_number
        });

        if let Some(idx) = idx {
            let mut sk = self.skipped_keys.remove(idx);
            let ad = bincode::serialize(header)
                .map_err(|e| Error::Serialization(e.to_string()))?;
            let plaintext = aead::decrypt(ciphertext, sk.message_key.as_bytes(), &ad)?;
            sk.zeroize();
            return Ok(Some(plaintext));
        }

        Ok(None)
    }
}

impl Zeroize for PqTripleRatchet {
    fn zeroize(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut chain) = self.sending_chain {
            chain.zeroize();
        }
        if let Some(ref mut chain) = self.receiving_chain {
            chain.zeroize();
        }
        for sk in &mut self.skipped_keys {
            sk.zeroize();
        }
    }
}

impl Drop for PqTripleRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::MlKemKeyPair;

    #[test]
    fn test_ratchet_roundtrip() {
        // Simulate X3DH-like shared secret establishment
        let bob_keypair = MlKemKeyPair::generate().unwrap();
        let (_, shared_secret) = bob_keypair.public_key().encapsulate().unwrap();

        // Alice initiates
        let mut alice = PqTripleRatchet::init_initiator(
            shared_secret.clone(),
            bob_keypair.public_key().clone(),
        ).unwrap();

        // Bob responds
        let mut bob = PqTripleRatchet::init_responder(
            shared_secret,
            bob_keypair,
        ).unwrap();

        // Alice sends
        let plaintext = b"Hello, Bob!";
        let (header, ciphertext) = alice.encrypt(plaintext).unwrap();

        // Bob receives
        let decrypted = bob.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
