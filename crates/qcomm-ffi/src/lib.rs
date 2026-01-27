//! C FFI bindings for Quantum Communicator
//!
//! Provides bindings for iOS (Swift) and Android (Kotlin) via UniFFI.

use std::sync::Arc;
use thiserror::Error;

// Re-export core types
pub use qcomm_core::{Config, Identity, Fingerprint};

/// FFI-safe error type
#[derive(Debug, Error)]
pub enum QCommError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<qcomm_core::Error> for QCommError {
    fn from(e: qcomm_core::Error) -> Self {
        match e {
            qcomm_core::Error::KeyGeneration(s)
            | qcomm_core::Error::Encryption(s)
            | qcomm_core::Error::Decryption(s)
            | qcomm_core::Error::KeyExchange(s) => QCommError::Crypto(s),

            qcomm_core::Error::Ble(s)
            | qcomm_core::Error::Nostr(s)
            | qcomm_core::Error::Connection(s) => QCommError::Transport(s),

            qcomm_core::Error::InvalidMessage(s) => QCommError::Protocol(s),
            qcomm_core::Error::ProtocolMismatch { expected, actual } => {
                QCommError::Protocol(format!("Version mismatch: expected {}, got {}", expected, actual))
            }

            qcomm_core::Error::Config(s) => QCommError::Config(s),

            _ => QCommError::Internal(e.to_string()),
        }
    }
}

/// Result type for FFI
pub type QCommResult<T> = Result<T, QCommError>;

/// FFI-safe identity wrapper
pub struct FFIIdentity {
    inner: Identity,
}

impl FFIIdentity {
    /// Generate a new identity
    pub fn generate() -> QCommResult<Arc<Self>> {
        let inner = Identity::generate()?;
        Ok(Arc::new(Self { inner }))
    }

    /// Get fingerprint as hex string
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint().to_hex()
    }

    /// Get public key as bytes
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().as_bytes().to_vec()
    }

    /// Sign a message
    pub fn sign(&self, message: Vec<u8>) -> QCommResult<Vec<u8>> {
        self.inner.sign(&message).map_err(Into::into)
    }

    /// Verify a signature
    pub fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> QCommResult<bool> {
        self.inner.verify(&message, &signature).map_err(Into::into)
    }
}

/// FFI-safe message wrapper
pub struct FFIMessage {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub text: Option<String>,
    pub timestamp: u64,
    pub pqc_encrypted: bool,
}

impl FFIMessage {
    /// Create a text message
    pub fn text(sender: String, recipient: String, text: String) -> Arc<Self> {
        let msg = qcomm_core::protocol::Message::text(&sender, &recipient, &text);
        Arc::new(Self {
            id: msg.id,
            sender: msg.sender,
            recipient: msg.recipient,
            text: Some(text),
            timestamp: msg.timestamp,
            pqc_encrypted: msg.metadata.pqc_encrypted,
        })
    }
}

/// FFI-safe channel wrapper
pub struct FFIChannel {
    pub id: String,
    pub name: String,
    pub channel_type: String,
    pub encrypted: bool,
    pub pqc_enabled: bool,
    pub unread_count: u32,
}

impl FFIChannel {
    /// Create a DM channel
    pub fn dm(our_fingerprint: String, their_fingerprint: String) -> Arc<Self> {
        let ch = qcomm_core::protocol::Channel::direct(&our_fingerprint, &their_fingerprint);
        Arc::new(Self {
            id: ch.id,
            name: ch.name,
            channel_type: "direct".to_string(),
            encrypted: ch.encrypted,
            pqc_enabled: ch.pqc_enabled,
            unread_count: ch.unread_count,
        })
    }

    /// Create a group channel
    pub fn group(name: String, creator: String) -> Arc<Self> {
        let ch = qcomm_core::protocol::Channel::group(&name, &creator);
        Arc::new(Self {
            id: ch.id,
            name: ch.name,
            channel_type: "group".to_string(),
            encrypted: ch.encrypted,
            pqc_enabled: ch.pqc_enabled,
            unread_count: ch.unread_count,
        })
    }

    /// Create a forum channel
    pub fn forum(name: String) -> Arc<Self> {
        let ch = qcomm_core::protocol::Channel::forum(&name);
        Arc::new(Self {
            id: ch.id,
            name: ch.name,
            channel_type: "forum".to_string(),
            encrypted: ch.encrypted,
            pqc_enabled: ch.pqc_enabled,
            unread_count: ch.unread_count,
        })
    }
}

/// Get random bytes
pub fn get_random_bytes(count: u32) -> QCommResult<Vec<u8>> {
    qcomm_core::crypto::qrng::get_entropy(count as usize).map_err(Into::into)
}

/// Check if hardware QRNG is available
pub fn is_qrng_available() -> bool {
    qcomm_core::crypto::qrng::is_hardware_available()
}

/// Get library version
pub fn version() -> String {
    qcomm_core::VERSION.to_string()
}

// Note: In production, generate UniFFI scaffolding via build.rs
// uniffi::include_scaffolding!("qcomm");
