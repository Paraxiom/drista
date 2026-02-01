//! WASM-compatible PQ-Triple-Ratchet Protocol
//!
//! Uses ml-kem (pure Rust) for WASM compatibility.

use crate::crypto::pq_wasm::{MlKemKeyPair, MlKemPublicKey, SharedSecret};
use crate::crypto::aead;
use crate::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const CHAIN_KEY_SIZE: usize = 32;
const MESSAGE_KEY_SIZE: usize = 32;
const MAX_SKIP: usize = 1000;

const ROOT_INFO: &[u8] = b"QuantumCommunicator_RootChain_v1";
const CHAIN_INFO: &[u8] = b"QuantumCommunicator_ChainKey_v1";
const MESSAGE_INFO: &[u8] = b"QuantumCommunicator_MessageKey_v1";

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

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct MessageKey([u8; MESSAGE_KEY_SIZE]);

impl MessageKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone)]
struct ChainState {
    chain_key: ChainKey,
    counter: u32,
}

impl ChainState {
    fn new(chain_key: ChainKey) -> Self {
        Self { chain_key, counter: 0 }
    }

    fn advance(&mut self) -> Result<MessageKey> {
        let hk = Hkdf::<Sha256>::new(None, self.chain_key.as_bytes());

        let mut next_chain_key = [0u8; CHAIN_KEY_SIZE];
        hk.expand(CHAIN_INFO, &mut next_chain_key)
            .map_err(|_| Error::RatchetCorrupted("Chain key derivation failed".into()))?;

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

/// Header for ratchet messages (serialized with message)
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetHeader {
    pub kem_public_key: Vec<u8>,
    pub previous_chain_length: u32,
    pub message_number: u32,
}

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

/// WASM-compatible PQ-Triple-Ratchet session
pub struct PqTripleRatchet {
    our_keypair: MlKemKeyPair,
    their_public_key: Option<MlKemPublicKey>,
    root_key: ChainKey,
    sending_chain: Option<ChainState>,
    receiving_chain: Option<ChainState>,
    previous_sending_length: u32,
    skipped_keys: Vec<SkippedKey>,
}

impl PqTripleRatchet {
    /// Initialize as session initiator (Alice)
    pub fn init_initiator(
        shared_secret: SharedSecret,
        their_public_key: MlKemPublicKey,
    ) -> Result<Self> {
        let our_keypair = MlKemKeyPair::generate()?;

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

    /// Initialize as session responder (Bob)
    pub fn init_responder(
        shared_secret: SharedSecret,
        our_keypair: MlKemKeyPair,
    ) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

        let mut root_key = [0u8; CHAIN_KEY_SIZE];
        hk.expand(ROOT_INFO, &mut root_key)
            .map_err(|_| Error::RatchetCorrupted("Root key derivation failed".into()))?;

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

    /// Get our current public key bytes
    pub fn our_public_key_bytes(&self) -> Vec<u8> {
        self.our_keypair.public_key().as_bytes().to_vec()
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>)> {
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

        let ad = bincode::serialize(&header)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let ciphertext = aead::encrypt(plaintext, message_key.as_bytes(), &ad)?;

        Ok((header, ciphertext))
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, header: &RatchetHeader, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if let Some(plaintext) = self.try_skipped_keys(header, ciphertext)? {
            return Ok(plaintext);
        }

        let their_pk = MlKemPublicKey::from_bytes(&header.kem_public_key)?;
        let their_pk_changed = self.their_public_key.as_ref()
            .map(|pk| pk.as_bytes() != their_pk.as_bytes())
            .unwrap_or(false);

        let is_first_message = self.their_public_key.is_none();

        if is_first_message {
            self.their_public_key = Some(their_pk);
        } else if their_pk_changed {
            self.skip_messages(header.previous_chain_length)?;
            self.dh_ratchet(their_pk)?;
        }

        self.skip_messages(header.message_number)?;

        let chain = self.receiving_chain.as_mut()
            .ok_or_else(|| Error::RatchetCorrupted("No receiving chain".into()))?;

        let message_key = chain.advance()?;

        let ad = bincode::serialize(header)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        aead::decrypt(ciphertext, message_key.as_bytes(), &ad)
    }

    fn dh_ratchet(&mut self, their_public_key: MlKemPublicKey) -> Result<()> {
        if let Some(ref chain) = self.sending_chain {
            self.previous_sending_length = chain.counter;
        }

        self.their_public_key = Some(their_public_key.clone());

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

    /// Serialize session state for storage
    pub fn serialize_state(&self) -> Result<Vec<u8>> {
        // For now, return an error - full state serialization requires careful design
        Err(Error::Serialization("Session serialization not yet implemented".into()))
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

    #[test]
    fn test_ratchet_roundtrip() {
        let bob_keypair = MlKemKeyPair::generate().unwrap();
        let (_, shared_secret) = bob_keypair.public_key().encapsulate().unwrap();

        let mut alice = PqTripleRatchet::init_initiator(
            shared_secret.clone(),
            bob_keypair.public_key().clone(),
        ).unwrap();

        let mut bob = PqTripleRatchet::init_responder(
            shared_secret,
            bob_keypair,
        ).unwrap();

        let plaintext = b"Hello, post-quantum world!";
        let (header, ciphertext) = alice.encrypt(plaintext).unwrap();

        let decrypted = bob.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_multiple_messages() {
        let bob_keypair = MlKemKeyPair::generate().unwrap();
        let (_, shared_secret) = bob_keypair.public_key().encapsulate().unwrap();

        let mut alice = PqTripleRatchet::init_initiator(
            shared_secret.clone(),
            bob_keypair.public_key().clone(),
        ).unwrap();

        let mut bob = PqTripleRatchet::init_responder(
            shared_secret,
            bob_keypair,
        ).unwrap();

        for i in 0..5 {
            let msg = format!("Message {}", i);
            let (header, ciphertext) = alice.encrypt(msg.as_bytes()).unwrap();
            let decrypted = bob.decrypt(&header, &ciphertext).unwrap();
            assert_eq!(decrypted, msg.as_bytes());
        }
    }
}
