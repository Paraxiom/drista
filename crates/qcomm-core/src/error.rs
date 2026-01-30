//! Error types for Quantum Communicator

use thiserror::Error;

/// Result type alias using our Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in Quantum Communicator
#[derive(Debug, Error)]
pub enum Error {
    // Crypto errors
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Key exchange failed: {0}")]
    KeyExchange(String),

    #[error("Ratchet state corrupted: {0}")]
    RatchetCorrupted(String),

    // QRNG errors
    #[error("QRNG unavailable: {0}")]
    QrngUnavailable(String),

    #[error("Insufficient entropy")]
    InsufficientEntropy,

    // QKD errors
    #[error("QKD channel not established")]
    QkdNotEstablished,

    #[error("QKD key exhausted")]
    QkdKeyExhausted,

    #[error("QKD connection failed: {0}")]
    QkdConnection(String),

    // Transport errors
    #[error("BLE error: {0}")]
    Ble(String),

    #[error("Nostr error: {0}")]
    Nostr(String),

    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Timeout")]
    Timeout,

    // Protocol errors
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    ProtocolMismatch { expected: u8, actual: u8 },

    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    #[error("Unknown peer: {0}")]
    UnknownPeer(String),

    // Node errors
    #[error("Node sync failed: {0}")]
    NodeSync(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Transaction failed: {0}")]
    Transaction(String),

    // AI errors
    #[error("AI agent error: {0}")]
    AiAgent(String),

    // General errors
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
