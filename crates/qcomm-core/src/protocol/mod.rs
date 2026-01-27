//! Protocol Layer - BitChat Compatible Message Format
//!
//! Implements message encoding/decoding compatible with BitChat
//! while supporting PQC extensions.

pub mod message;
pub mod handshake;
pub mod channel;

pub use message::{Message, MessageType};
pub use handshake::Handshake;
pub use channel::{Channel, ChannelType};

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Protocol version for compatibility checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Major version (breaking changes)
    pub major: u8,
    /// Minor version (features)
    pub minor: u8,
    /// Patch version (fixes)
    pub patch: u8,
}

impl ProtocolVersion {
    /// BitChat compatible version
    pub const BITCHAT: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    /// Quantum Communicator version
    pub const QCOMM: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    /// Check compatibility with another version
    pub fn is_compatible(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Peer capabilities advertised during handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Protocol version
    pub version: ProtocolVersion,
    /// Supports PQ-Triple-Ratchet
    pub pq_ratchet: bool,
    /// Supports QRNG
    pub qrng: bool,
    /// Supports QKD enhancement
    pub qkd: bool,
    /// Supports AI agents
    pub ai_agents: bool,
    /// Has blockchain node
    pub blockchain: bool,
    /// Supported transports
    pub transports: Vec<String>,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            version: ProtocolVersion::QCOMM,
            pq_ratchet: true,
            qrng: false,
            qkd: false,
            ai_agents: false,
            blockchain: false,
            transports: vec!["ble".into(), "nostr".into()],
        }
    }
}

impl PeerCapabilities {
    /// Create BitChat-compatible capabilities (no PQC)
    pub fn bitchat() -> Self {
        Self {
            version: ProtocolVersion::BITCHAT,
            pq_ratchet: false,
            qrng: false,
            qkd: false,
            ai_agents: false,
            blockchain: false,
            transports: vec!["ble".into(), "nostr".into()],
        }
    }

    /// Check if peer supports PQC
    pub fn supports_pqc(&self) -> bool {
        self.pq_ratchet
    }

    /// Negotiate common capabilities
    pub fn negotiate(&self, other: &Self) -> NegotiatedCapabilities {
        NegotiatedCapabilities {
            use_pqc: self.pq_ratchet && other.pq_ratchet,
            use_qrng: self.qrng && other.qrng,
            use_qkd: self.qkd && other.qkd,
        }
    }
}

/// Result of capability negotiation
#[derive(Debug, Clone)]
pub struct NegotiatedCapabilities {
    /// Use PQ-Triple-Ratchet
    pub use_pqc: bool,
    /// Use QRNG for key generation
    pub use_qrng: bool,
    /// Use QKD for key enhancement
    pub use_qkd: bool,
}
