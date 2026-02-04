//! Transport Layer for Quantum Communicator
//!
//! Supports multiple transport protocols:
//! - **BLE Mesh**: BitChat-compatible Bluetooth mesh networking
//! - **Nostr**: NIP-17 encrypted DMs with PQC extensions
//! - **QSSH**: Quantum-secure SSH tunneling
//! - **OnChain**: QuantumHarmony blockchain forum channel

#[cfg(feature = "native-crypto")]
pub mod ble;
#[cfg(feature = "native-crypto")]
pub mod nostr;
// QSSH transport (requires qssh-transport feature)
#[cfg(all(feature = "native-crypto", feature = "qssh-transport"))]
pub mod qssh;
#[cfg(feature = "native-crypto")]
pub mod onchain;

use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Message envelope for transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportMessage {
    /// Unique message ID
    pub id: String,
    /// Sender fingerprint
    pub from: String,
    /// Recipient fingerprint (or channel name)
    pub to: String,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
    /// Transport-specific metadata
    pub metadata: MessageMetadata,
}

/// Transport-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageMetadata {
    /// BLE mesh routing info
    Ble {
        hop_count: u8,
        ttl: u8,
    },
    /// Nostr event info
    Nostr {
        event_id: String,
        relay: String,
    },
    /// QSSH session info
    Qssh {
        session_id: String,
    },
    /// On-chain transaction
    OnChain {
        block_hash: String,
        tx_index: u32,
    },
}

/// Transport capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportCapability {
    /// Can send messages
    Send,
    /// Can receive messages
    Receive,
    /// Supports message persistence
    Persistence,
    /// Supports offline delivery
    OfflineDelivery,
    /// Supports group channels
    GroupChannel,
    /// Supports PQC
    PostQuantum,
}

/// Transport layer trait
#[async_trait]
pub trait Transport: Send + Sync {
    /// Get transport name
    fn name(&self) -> &str;

    /// Get supported capabilities
    fn capabilities(&self) -> Vec<TransportCapability>;

    /// Check if transport is connected
    async fn is_connected(&self) -> bool;

    /// Connect to the transport network
    async fn connect(&mut self) -> Result<()>;

    /// Disconnect from the transport network
    async fn disconnect(&mut self) -> Result<()>;

    /// Send a message
    async fn send(&self, message: TransportMessage) -> Result<()>;

    /// Receive next message (blocking)
    async fn receive(&mut self) -> Result<TransportMessage>;

    /// Check for new messages without blocking
    async fn poll(&mut self) -> Result<Option<TransportMessage>>;
}

/// Multi-transport manager
pub struct TransportManager {
    transports: Vec<Box<dyn Transport>>,
}

impl TransportManager {
    /// Create a new transport manager
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
        }
    }

    /// Add a transport
    pub fn add_transport(&mut self, transport: Box<dyn Transport>) {
        self.transports.push(transport);
    }

    /// Get all transports
    pub fn transports(&self) -> &[Box<dyn Transport>] {
        &self.transports
    }

    /// Connect all transports
    pub async fn connect_all(&mut self) -> Result<()> {
        for transport in &mut self.transports {
            if let Err(e) = transport.connect().await {
                tracing::warn!("Failed to connect {}: {}", transport.name(), e);
            }
        }
        Ok(())
    }

    /// Disconnect all transports
    pub async fn disconnect_all(&mut self) -> Result<()> {
        for transport in &mut self.transports {
            if let Err(e) = transport.disconnect().await {
                tracing::warn!("Failed to disconnect {}: {}", transport.name(), e);
            }
        }
        Ok(())
    }

    /// Send via best available transport
    pub async fn send(&self, message: TransportMessage) -> Result<()> {
        for transport in &self.transports {
            if transport.is_connected().await {
                return transport.send(message).await;
            }
        }
        Err(Error::Connection("No transports available".into()))
    }

    /// Poll all transports for messages
    pub async fn poll_all(&mut self) -> Vec<TransportMessage> {
        let mut messages = Vec::new();

        for transport in &mut self.transports {
            while let Ok(Some(msg)) = transport.poll().await {
                messages.push(msg);
            }
        }

        messages
    }
}

impl Default for TransportManager {
    fn default() -> Self {
        Self::new()
    }
}
