//! On-Chain Transport for QuantumHarmony Blockchain
//!
//! Provides persistent, censorship-resistant messaging via the
//! QuantumHarmony blockchain forum channel.

use super::{Transport, TransportCapability, TransportMessage, MessageMetadata};
use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Forum message stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumMessage {
    /// Message ID (transaction hash)
    pub id: String,
    /// Channel name (e.g., "#quantum")
    pub channel: String,
    /// Author fingerprint
    pub author: String,
    /// Message content (may be encrypted)
    pub content: String,
    /// Timestamp (block time)
    pub timestamp: u64,
    /// Block hash containing this message
    pub block_hash: String,
    /// Transaction index in block
    pub tx_index: u32,
    /// Reply to message ID (optional)
    pub reply_to: Option<String>,
}

/// Block info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block hash
    pub hash: String,
    /// Block number
    pub number: u64,
    /// Parent hash
    pub parent_hash: String,
    /// Timestamp
    pub timestamp: u64,
    /// Number of transactions
    pub tx_count: u32,
}

/// On-chain transport configuration
#[derive(Debug, Clone)]
pub struct OnChainConfig {
    /// RPC endpoint
    pub rpc_endpoint: String,
    /// Default channel to monitor
    pub default_channel: String,
    /// Our fingerprint for posting
    pub our_fingerprint: String,
}

impl Default for OnChainConfig {
    fn default() -> Self {
        Self {
            rpc_endpoint: "http://localhost:9944".into(),
            default_channel: "#quantum".into(),
            our_fingerprint: String::new(),
        }
    }
}

/// On-chain transport
pub struct OnChainTransport {
    /// Configuration
    config: OnChainConfig,
    /// RPC client connected state
    connected: bool,
    /// Subscribed channels
    subscribed_channels: Vec<String>,
    /// Incoming message queue
    incoming: Arc<Mutex<VecDeque<TransportMessage>>>,
    /// Last synced block
    last_block: Arc<Mutex<u64>>,
}

impl OnChainTransport {
    /// Create a new on-chain transport
    pub fn new(config: OnChainConfig) -> Self {
        Self {
            config,
            connected: false,
            subscribed_channels: vec![],
            incoming: Arc::new(Mutex::new(VecDeque::new())),
            last_block: Arc::new(Mutex::new(0)),
        }
    }

    /// Subscribe to a channel
    pub fn subscribe_channel(&mut self, channel: &str) {
        if !self.subscribed_channels.contains(&channel.to_string()) {
            self.subscribed_channels.push(channel.to_string());
            tracing::info!("Subscribed to on-chain channel: {}", channel);
        }
    }

    /// Get latest block info
    pub async fn get_latest_block(&self) -> Result<BlockInfo> {
        if !self.connected {
            return Err(Error::NodeSync("Not connected".into()));
        }

        // In production, would call RPC:
        // POST {"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}

        Ok(BlockInfo {
            hash: "0x".to_string() + &"0".repeat(64),
            number: *self.last_block.lock().await,
            parent_hash: "0x".to_string() + &"0".repeat(64),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            tx_count: 0,
        })
    }

    /// Post a message to a channel
    pub async fn post_message(&self, channel: &str, content: &str) -> Result<String> {
        if !self.connected {
            return Err(Error::NodeSync("Not connected".into()));
        }

        // In production, would:
        // 1. Create unsigned transaction
        // 2. Sign with SPHINCS+ key
        // 3. Submit to node
        // 4. Wait for inclusion in block

        let tx_hash = format!("0x{:064x}", rand::random::<u128>());

        tracing::info!(
            "Posted message to {} (tx: {})",
            channel,
            &tx_hash[..10]
        );

        Ok(tx_hash)
    }

    /// Fetch messages from a channel
    pub async fn fetch_messages(
        &self,
        channel: &str,
        from_block: u64,
        limit: usize,
    ) -> Result<Vec<ForumMessage>> {
        if !self.connected {
            return Err(Error::NodeSync("Not connected".into()));
        }

        // In production, would query the chain for forum events
        // in the specified block range

        tracing::debug!(
            "Fetching messages from {} (blocks {} onwards, limit {})",
            channel,
            from_block,
            limit
        );

        Ok(Vec::new())
    }

    /// Sync new messages from subscribed channels
    async fn sync_messages(&self) -> Result<Vec<ForumMessage>> {
        let from_block = *self.last_block.lock().await;
        let mut all_messages = Vec::new();

        for channel in &self.subscribed_channels {
            let messages = self.fetch_messages(channel, from_block, 100).await?;
            all_messages.extend(messages);
        }

        // Update last block
        if let Ok(latest) = self.get_latest_block().await {
            *self.last_block.lock().await = latest.number;
        }

        Ok(all_messages)
    }

    /// Convert forum message to transport message
    fn to_transport_message(msg: ForumMessage) -> TransportMessage {
        TransportMessage {
            id: msg.id.clone(),
            from: msg.author,
            to: msg.channel,
            payload: msg.content.into_bytes(),
            timestamp: msg.timestamp * 1000,
            metadata: MessageMetadata::OnChain {
                block_hash: msg.block_hash,
                tx_index: msg.tx_index,
            },
        }
    }
}

#[async_trait]
impl Transport for OnChainTransport {
    fn name(&self) -> &str {
        "OnChain"
    }

    fn capabilities(&self) -> Vec<TransportCapability> {
        vec![
            TransportCapability::Send,
            TransportCapability::Receive,
            TransportCapability::Persistence,
            TransportCapability::GroupChannel,
        ]
    }

    async fn is_connected(&self) -> bool {
        self.connected
    }

    async fn connect(&mut self) -> Result<()> {
        // In production, would:
        // 1. Connect to RPC endpoint
        // 2. Verify chain ID
        // 3. Start block subscription

        tracing::info!("Connecting to {}", self.config.rpc_endpoint);

        self.connected = true;

        // Subscribe to default channel
        self.subscribe_channel(&self.config.default_channel.clone());

        // Initial sync
        let messages = self.sync_messages().await?;
        let mut incoming = self.incoming.lock().await;
        for msg in messages {
            incoming.push_back(Self::to_transport_message(msg));
        }

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        self.subscribed_channels.clear();
        Ok(())
    }

    async fn send(&self, message: TransportMessage) -> Result<()> {
        // Treat 'to' as channel name
        let channel = if message.to.starts_with('#') {
            &message.to
        } else {
            // DM - use encrypted channel
            return Err(Error::Transaction(
                "Direct messages should use other transports".into(),
            ));
        };

        let content = String::from_utf8(message.payload)
            .map_err(|_| Error::InvalidMessage("Invalid UTF-8 content".into()))?;

        self.post_message(channel, &content).await?;

        Ok(())
    }

    async fn receive(&mut self) -> Result<TransportMessage> {
        loop {
            // Check queue
            if let Some(msg) = self.incoming.lock().await.pop_front() {
                return Ok(msg);
            }

            // Sync new messages
            let messages = self.sync_messages().await?;
            if !messages.is_empty() {
                let mut incoming = self.incoming.lock().await;
                for msg in messages {
                    incoming.push_back(Self::to_transport_message(msg));
                }
                continue;
            }

            // Wait for new blocks
            tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

            if !self.connected {
                return Err(Error::NodeSync("Disconnected".into()));
            }
        }
    }

    async fn poll(&mut self) -> Result<Option<TransportMessage>> {
        // Quick sync check
        if let Ok(messages) = self.sync_messages().await {
            let mut incoming = self.incoming.lock().await;
            for msg in messages {
                incoming.push_back(Self::to_transport_message(msg));
            }
        }

        Ok(self.incoming.lock().await.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_onchain_transport() {
        let config = OnChainConfig::default();
        let transport = OnChainTransport::new(config);

        assert!(!transport.is_connected().await);
        assert_eq!(transport.name(), "OnChain");
    }

    #[test]
    fn test_forum_message_serialization() {
        let msg = ForumMessage {
            id: "0x123".into(),
            channel: "#quantum".into(),
            author: "abc".into(),
            content: "Hello".into(),
            timestamp: 12345,
            block_hash: "0x456".into(),
            tx_index: 0,
            reply_to: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ForumMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.channel, "#quantum");
    }
}
