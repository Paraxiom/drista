//! # Quantum Communicator Core
//!
//! A post-quantum secure chat library compatible with BitChat protocol.
//!
//! ## Features
//!
//! - **PQ-Triple-Ratchet**: ML-KEM + SPHINCS+ based forward-secure encryption
//! - **BitChat Compatibility**: Speaks native BLE mesh and Nostr protocols
//! - **QRNG Integration**: Hardware quantum random number generation
//! - **QKD Enhancement**: Quantum key distribution when hardware available
//! - **QuantumHarmony Node**: Embedded light client for on-chain features
//! - **AI Agents**: Built-in agent framework for automated channel participation

pub mod crypto;
#[cfg(feature = "native-crypto")]
pub mod transport;
#[cfg(feature = "native-crypto")]
pub mod protocol;
#[cfg(feature = "native-crypto")]
pub mod node;
#[cfg(feature = "native-crypto")]
pub mod ai;

mod error;
#[cfg(feature = "native-crypto")]
mod identity;

pub use error::{Error, Result};
#[cfg(feature = "native-crypto")]
pub use identity::{Identity, Fingerprint};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol version for BitChat compatibility
pub const BITCHAT_PROTOCOL_VERSION: u8 = 1;

/// PQC extension protocol version
pub const PQC_PROTOCOL_VERSION: u8 = 1;

/// Configuration for the Quantum Communicator
#[derive(Debug, Clone)]
pub struct Config {
    /// Enable post-quantum cryptography (default: true)
    pub enable_pqc: bool,

    /// Fall back to Noise protocol for BitChat compat (default: true)
    pub enable_noise_fallback: bool,

    /// Use hardware QRNG when available (default: true)
    pub enable_qrng: bool,

    /// Use QKD enhancement when available (default: true)
    pub enable_qkd: bool,

    /// Run QuantumHarmony light client (default: true)
    pub enable_node: bool,

    /// Enable validator mode (default: false)
    pub enable_validator: bool,

    /// Enable AI agent features (default: false)
    pub enable_ai_agent: bool,

    /// Nostr relays to connect to
    pub nostr_relays: Vec<String>,

    /// QuantumHarmony RPC endpoint
    pub node_rpc: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_pqc: true,
            enable_noise_fallback: true,
            enable_qrng: true,
            enable_qkd: true,
            enable_node: true,
            enable_validator: false,
            enable_ai_agent: false,
            nostr_relays: vec![
                "wss://relay.damus.io".into(),
                "wss://nos.lol".into(),
                "wss://relay.nostr.band".into(),
            ],
            node_rpc: "http://localhost:9944".into(),
        }
    }
}

/// Main entry point for Quantum Communicator
#[cfg(feature = "native-crypto")]
pub struct QuantumCommunicator {
    config: Config,
    identity: Identity,
}

#[cfg(feature = "native-crypto")]
impl QuantumCommunicator {
    /// Create a new Quantum Communicator instance
    pub fn new(config: Config) -> Result<Self> {
        let identity = Identity::generate()?;
        Ok(Self { config, identity })
    }

    /// Create from existing identity
    pub fn with_identity(config: Config, identity: Identity) -> Self {
        Self { config, identity }
    }

    /// Get the current identity
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}
