//! QuantumHarmony Node Integration
//!
//! Embedded light client for blockchain features:
//! - Block synchronization
//! - On-chain forum posting
//! - Validator identity
//! - Transaction submission

pub mod client;
pub mod sync;
pub mod validator;

pub use client::LightClient;
pub use sync::SyncState;
pub use validator::ValidatorMode;

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block hash
    pub hash: String,
    /// Block number
    pub number: u64,
    /// Parent hash
    pub parent_hash: String,
    /// State root
    pub state_root: String,
    /// Extrinsics root
    pub extrinsics_root: String,
    /// Timestamp
    pub timestamp: u64,
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxReceipt {
    /// Transaction hash
    pub tx_hash: String,
    /// Block hash
    pub block_hash: String,
    /// Block number
    pub block_number: u64,
    /// Transaction index in block
    pub tx_index: u32,
    /// Success status
    pub success: bool,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// RPC request
#[derive(Debug, Clone, Serialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

impl RpcRequest {
    pub fn new(id: u64, method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

/// RPC response
#[derive(Debug, Clone, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<serde_json::Value>,
    pub error: Option<RpcError>,
}

/// RPC error
#[derive(Debug, Clone, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}
