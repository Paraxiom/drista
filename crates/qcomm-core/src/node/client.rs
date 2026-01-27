//! Light Client for QuantumHarmony

use super::{BlockHeader, RpcRequest, RpcResponse, TxReceipt};
use crate::{Error, Result, Identity};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Light client configuration
#[derive(Debug, Clone)]
pub struct LightClientConfig {
    /// RPC endpoint URL
    pub rpc_url: String,
    /// WebSocket endpoint for subscriptions
    pub ws_url: Option<String>,
    /// Enable light sync (headers only)
    pub light_sync: bool,
    /// Sync from this block (0 = genesis)
    pub sync_from: u64,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:9944".to_string(),
            ws_url: Some("ws://localhost:9944".to_string()),
            light_sync: true,
            sync_from: 0,
        }
    }
}

/// Light client state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Not started
    Stopped,
    /// Connecting to node
    Connecting,
    /// Syncing blocks
    Syncing,
    /// Synced and ready
    Ready,
    /// Error state
    Error,
}

/// QuantumHarmony light client
pub struct LightClient {
    /// Configuration
    config: LightClientConfig,
    /// Current state
    state: Arc<Mutex<ClientState>>,
    /// Latest synced block
    latest_block: Arc<Mutex<Option<BlockHeader>>>,
    /// Request ID counter
    request_id: AtomicU64,
    /// HTTP client
    #[cfg(feature = "reqwest")]
    http_client: reqwest::Client,
}

impl LightClient {
    /// Create a new light client
    pub fn new(config: LightClientConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ClientState::Stopped)),
            latest_block: Arc::new(Mutex::new(None)),
            request_id: AtomicU64::new(1),
            #[cfg(feature = "reqwest")]
            http_client: reqwest::Client::new(),
        }
    }

    /// Get current state
    pub async fn state(&self) -> ClientState {
        *self.state.lock().await
    }

    /// Get latest synced block
    pub async fn latest_block(&self) -> Option<BlockHeader> {
        self.latest_block.lock().await.clone()
    }

    /// Get sync height
    pub async fn sync_height(&self) -> u64 {
        self.latest_block
            .lock()
            .await
            .as_ref()
            .map(|b| b.number)
            .unwrap_or(0)
    }

    /// Start the light client
    pub async fn start(&self) -> Result<()> {
        *self.state.lock().await = ClientState::Connecting;

        // Test connection
        match self.rpc_call("system_chain", json!([])).await {
            Ok(_) => {
                *self.state.lock().await = ClientState::Syncing;
                self.sync().await?;
                *self.state.lock().await = ClientState::Ready;
                Ok(())
            }
            Err(e) => {
                *self.state.lock().await = ClientState::Error;
                Err(e)
            }
        }
    }

    /// Stop the light client
    pub async fn stop(&self) {
        *self.state.lock().await = ClientState::Stopped;
    }

    /// Sync to latest block
    async fn sync(&self) -> Result<()> {
        let header = self.get_finalized_head().await?;
        *self.latest_block.lock().await = Some(header);
        Ok(())
    }

    /// Make an RPC call
    pub async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let request = RpcRequest::new(id, method, params);

        #[cfg(feature = "reqwest")]
        {
            let response = self
                .http_client
                .post(&self.config.rpc_url)
                .json(&request)
                .send()
                .await
                .map_err(|e| Error::Rpc(e.to_string()))?;

            let rpc_response: RpcResponse = response
                .json()
                .await
                .map_err(|e| Error::Rpc(e.to_string()))?;

            if let Some(error) = rpc_response.error {
                return Err(Error::Rpc(error.message));
            }

            rpc_response.result.ok_or_else(|| Error::Rpc("No result".into()))
        }

        #[cfg(not(feature = "reqwest"))]
        {
            // Simulated response for testing
            Ok(json!({}))
        }
    }

    /// Get finalized block header
    pub async fn get_finalized_head(&self) -> Result<BlockHeader> {
        let hash = self.rpc_call("chain_getFinalizedHead", json!([])).await?;
        let header = self
            .rpc_call("chain_getHeader", json!([hash]))
            .await?;

        Ok(BlockHeader {
            hash: hash.as_str().unwrap_or_default().to_string(),
            number: header["number"]
                .as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0),
            parent_hash: header["parentHash"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            state_root: header["stateRoot"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            extrinsics_root: header["extrinsicsRoot"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            timestamp: 0, // Would fetch from timestamp pallet
        })
    }

    /// Submit a signed transaction
    pub async fn submit_transaction(&self, signed_tx: &[u8]) -> Result<String> {
        let tx_hex = format!("0x{}", hex::encode(signed_tx));
        let result = self
            .rpc_call("author_submitExtrinsic", json!([tx_hex]))
            .await?;

        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Transaction("Invalid response".into()))
    }

    /// Post a message to the on-chain forum
    pub async fn post_forum_message(
        &self,
        identity: &Identity,
        channel: &str,
        content: &str,
    ) -> Result<TxReceipt> {
        // In production, would:
        // 1. Encode the forum.postMessage extrinsic
        // 2. Sign with identity's SPHINCS+ key
        // 3. Submit and wait for inclusion

        let _call_data = json!({
            "module": "forum",
            "call": "postMessage",
            "args": {
                "channel": channel,
                "content": content,
            }
        });

        // Simulate success for now
        Ok(TxReceipt {
            tx_hash: format!("0x{:064x}", rand::random::<u128>()),
            block_hash: self
                .latest_block
                .lock()
                .await
                .as_ref()
                .map(|b| b.hash.clone())
                .unwrap_or_default(),
            block_number: self.sync_height().await + 1,
            tx_index: 0,
            success: true,
            error: None,
        })
    }

    /// Query forum messages
    pub async fn query_forum_messages(
        &self,
        channel: &str,
        from_block: u64,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        // In production, would query storage or events
        let _params = json!({
            "channel": channel,
            "from": from_block,
            "limit": limit,
        });

        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_light_client_creation() {
        let config = LightClientConfig::default();
        let client = LightClient::new(config);
        assert_eq!(client.state().await, ClientState::Stopped);
    }

    #[tokio::test]
    async fn test_sync_height() {
        let client = LightClient::new(LightClientConfig::default());
        assert_eq!(client.sync_height().await, 0);
    }
}
