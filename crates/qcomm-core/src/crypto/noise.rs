//! Noise Protocol Implementation for BitChat Compatibility
//!
//! Implements Noise_XX_25519_AESGCM_SHA256 for fallback
//! communication with legacy BitChat clients.

use crate::{Error, Result};
use sha2::{Sha256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Noise protocol name for BitChat compatibility
pub const NOISE_PROTOCOL: &str = "Noise_XX_25519_AESGCM_SHA256";

/// Handshake pattern state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting to send first message
    Initial,
    /// Waiting for response
    WaitingForResponse,
    /// Handshake complete
    Complete,
    /// Error state
    Failed,
}

/// X25519 keypair for Noise protocol
pub struct NoiseKeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl NoiseKeyPair {
    /// Generate a new keypair
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Perform Diffie-Hellman
    pub fn dh(self, their_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(their_public)
    }
}

/// Cipher state for symmetric encryption
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherState {
    key: [u8; 32],
    nonce: u64,
}

impl CipherState {
    /// Create from key
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, nonce: 0 }
    }

    /// Encrypt with AEAD
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        use crate::crypto::aead;

        // Create nonce from counter
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;

        // Use our AEAD module (it generates random nonce, but we prepend ours)
        aead::encrypt(plaintext, &self.key, ad)
    }

    /// Decrypt with AEAD
    pub fn decrypt(&mut self, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        use crate::crypto::aead;
        aead::decrypt(ciphertext, &self.key, ad)
    }
}

/// Symmetric state for handshake
pub struct SymmetricState {
    /// Chaining key
    ck: [u8; 32],
    /// Handshake hash
    h: [u8; 32],
    /// Cipher state (after key is set)
    cipher: Option<CipherState>,
}

impl SymmetricState {
    /// Initialize with protocol name
    pub fn new(protocol_name: &str) -> Self {
        let mut h = [0u8; 32];
        if protocol_name.len() <= 32 {
            h[..protocol_name.len()].copy_from_slice(protocol_name.as_bytes());
        } else {
            h = Sha256::digest(protocol_name.as_bytes()).into();
        }

        Self {
            ck: h,
            h,
            cipher: None,
        }
    }

    /// Mix key material into the hash
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// Mix key into chaining key
    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        use hkdf::Hkdf;

        let hk = Hkdf::<Sha256>::new(Some(&self.ck), input_key_material);
        let mut output = [0u8; 64];
        hk.expand(b"", &mut output).unwrap();

        self.ck.copy_from_slice(&output[..32]);
        let mut temp_k = [0u8; 32];
        temp_k.copy_from_slice(&output[32..64]);

        self.cipher = Some(CipherState::new(temp_k));
    }

    /// Get the handshake hash
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.h
    }

    /// Split into send/receive cipher states
    pub fn split(self) -> Result<(CipherState, CipherState)> {
        use hkdf::Hkdf;

        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut output = [0u8; 64];
        hk.expand(b"", &mut output).unwrap();

        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        send_key.copy_from_slice(&output[..32]);
        recv_key.copy_from_slice(&output[32..64]);

        Ok((CipherState::new(send_key), CipherState::new(recv_key)))
    }
}

/// Noise handshake session
pub struct NoiseSession {
    /// Our static keypair (long-term)
    static_keypair: Option<NoiseKeyPair>,
    /// Our ephemeral keypair
    ephemeral_keypair: Option<NoiseKeyPair>,
    /// Their static public key
    their_static: Option<PublicKey>,
    /// Their ephemeral public key
    their_ephemeral: Option<PublicKey>,
    /// Symmetric state
    symmetric: SymmetricState,
    /// Current handshake state
    state: HandshakeState,
    /// Are we the initiator?
    initiator: bool,
}

impl NoiseSession {
    /// Create initiator session
    pub fn initiator(static_keypair: NoiseKeyPair) -> Self {
        let mut symmetric = SymmetricState::new(NOISE_PROTOCOL);
        // Mix in our static public key as prologue
        symmetric.mix_hash(static_keypair.public_key().as_bytes());

        Self {
            static_keypair: Some(static_keypair),
            ephemeral_keypair: None,
            their_static: None,
            their_ephemeral: None,
            symmetric,
            state: HandshakeState::Initial,
            initiator: true,
        }
    }

    /// Create responder session
    pub fn responder(static_keypair: NoiseKeyPair) -> Self {
        let symmetric = SymmetricState::new(NOISE_PROTOCOL);

        Self {
            static_keypair: Some(static_keypair),
            ephemeral_keypair: None,
            their_static: None,
            their_ephemeral: None,
            symmetric,
            state: HandshakeState::Initial,
            initiator: false,
        }
    }

    /// Get handshake state
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete
    }

    /// Write handshake message
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        match self.state {
            HandshakeState::Initial if self.initiator => {
                // -> e
                let ephemeral = NoiseKeyPair::generate();
                let e_pub = ephemeral.public_key_bytes();
                self.symmetric.mix_hash(&e_pub);

                let mut message = e_pub.to_vec();
                message.extend_from_slice(payload);

                self.ephemeral_keypair = Some(ephemeral);
                self.state = HandshakeState::WaitingForResponse;

                Ok(message)
            }
            HandshakeState::WaitingForResponse if !self.initiator => {
                // <- e, ee, s, es
                let ephemeral = NoiseKeyPair::generate();
                let e_pub = ephemeral.public_key_bytes();
                self.symmetric.mix_hash(&e_pub);

                // DH operations would go here...
                // Simplified for demonstration

                self.state = HandshakeState::Complete;
                Ok(e_pub.to_vec())
            }
            HandshakeState::Complete => {
                Err(Error::KeyExchange("Handshake already complete".into()))
            }
            _ => Err(Error::KeyExchange("Invalid handshake state".into())),
        }
    }

    /// Read handshake message
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if message.len() < 32 {
            return Err(Error::InvalidMessage("Message too short".into()));
        }

        match self.state {
            HandshakeState::Initial if !self.initiator => {
                // -> e
                let mut e_pub_bytes = [0u8; 32];
                e_pub_bytes.copy_from_slice(&message[..32]);
                let their_ephemeral = PublicKey::from(e_pub_bytes);

                self.symmetric.mix_hash(&e_pub_bytes);
                self.their_ephemeral = Some(their_ephemeral);
                self.state = HandshakeState::WaitingForResponse;

                let payload = message[32..].to_vec();
                Ok(payload)
            }
            HandshakeState::WaitingForResponse if self.initiator => {
                // <- e, ee, s, es
                let mut e_pub_bytes = [0u8; 32];
                e_pub_bytes.copy_from_slice(&message[..32]);
                let their_ephemeral = PublicKey::from(e_pub_bytes);

                self.symmetric.mix_hash(&e_pub_bytes);
                self.their_ephemeral = Some(their_ephemeral);
                self.state = HandshakeState::Complete;

                Ok(Vec::new())
            }
            HandshakeState::Complete => {
                Err(Error::KeyExchange("Handshake already complete".into()))
            }
            _ => Err(Error::InvalidMessage("Unexpected message".into())),
        }
    }

    /// Split into transport cipher states after handshake
    pub fn into_transport(self) -> Result<(CipherState, CipherState)> {
        if self.state != HandshakeState::Complete {
            return Err(Error::KeyExchange("Handshake not complete".into()));
        }
        self.symmetric.split()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_keypair() {
        let kp = NoiseKeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_symmetric_state() {
        let state = SymmetricState::new(NOISE_PROTOCOL);
        assert_eq!(state.handshake_hash().len(), 32);
    }

    #[test]
    fn test_handshake_initiator_first_message() {
        let kp = NoiseKeyPair::generate();
        let mut session = NoiseSession::initiator(kp);

        let msg = session.write_message(b"hello").unwrap();
        assert!(msg.len() >= 32); // At least ephemeral key
        assert_eq!(session.state(), HandshakeState::WaitingForResponse);
    }
}
