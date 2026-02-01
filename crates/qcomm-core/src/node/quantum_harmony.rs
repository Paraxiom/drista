//! QuantumHarmony Blockchain Integration
//!
//! Provides quantum-safe RPC access to QuantumHarmony validators via QSSH transport.
//!
//! ## Features
//! - RPC-over-QSSH (quantum-safe alternative to HTTP/WebSocket)
//! - Notarial pallet integration (document attestation)
//! - Ricardian contracts pallet integration (multi-party contracts)
//! - SPHINCS+ signature support for transactions

use super::{BlockHeader, RpcRequest, RpcResponse, TxReceipt};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// QuantumHarmony client configuration
#[derive(Debug, Clone)]
pub struct QuantumHarmonyConfig {
    /// Validator QSSH endpoint (e.g., "validator.quantum:42")
    pub qssh_endpoint: String,
    /// Fallback HTTP RPC endpoint (for non-quantum connections)
    pub http_endpoint: Option<String>,
    /// Username for QSSH authentication
    pub username: String,
    /// Security tier (T1-T5)
    pub security_tier: SecurityTier,
    /// Enable QKD enhancement when available
    pub enable_qkd: bool,
}

impl Default for QuantumHarmonyConfig {
    fn default() -> Self {
        Self {
            qssh_endpoint: "localhost:42".to_string(),
            http_endpoint: Some("http://localhost:9944".to_string()),
            username: whoami::username(),
            security_tier: SecurityTier::HardenedPQ,
            enable_qkd: true,
        }
    }
}

/// Security tier for quantum protection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityTier {
    /// T1: Post-quantum signatures only
    PostQuantum,
    /// T2: Hardened PQ with SPHINCS+ (default)
    HardenedPQ,
    /// T3: Entropy enhanced with hardware QRNG
    EntropyEnhanced,
    /// T4: QKD-secured session keys
    QuantumSecured,
    /// T5: Full hybrid quantum (QKD + PQC + classical)
    HybridQuantum,
}

/// Document attestation for notarial pallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentAttestation {
    /// Document hash (SHA-256)
    pub document_hash: String,
    /// Document title
    pub title: String,
    /// Category (Academic, Legal, Contract, etc.)
    pub category: DocumentCategory,
    /// IPFS CID for document storage
    pub ipfs_cid: Option<String>,
    /// Timestamp of attestation
    pub timestamp: u64,
    /// Block hash of attestation
    pub block_hash: Option<String>,
    /// Attester's SS58 address
    pub attester: String,
}

/// Document category
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DocumentCategory {
    Academic,
    Legal,
    Contract,
    IntellectualProperty,
    Identity,
    Financial,
    Medical,
    Other,
}

impl DocumentCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Academic => "Academic",
            Self::Legal => "Legal",
            Self::Contract => "Contract",
            Self::IntellectualProperty => "IP",
            Self::Identity => "Identity",
            Self::Financial => "Financial",
            Self::Medical => "Medical",
            Self::Other => "Other",
        }
    }
}

/// Witness signature for attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    /// Witness SS58 address
    pub witness: String,
    /// SPHINCS+ signature (hex-encoded)
    pub signature: String,
    /// Timestamp of witnessing
    pub timestamp: u64,
}

/// Ricardian contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RicardianContract {
    /// Contract ID (on-chain hash)
    pub contract_id: String,
    /// Contract title
    pub title: String,
    /// Human-readable terms
    pub terms: String,
    /// Machine-readable clauses
    pub clauses: Vec<ContractClause>,
    /// Required signatories
    pub parties: Vec<ContractParty>,
    /// Contract status
    pub status: ContractStatus,
    /// Creation timestamp
    pub created_at: u64,
    /// IPFS CID for full contract
    pub ipfs_cid: Option<String>,
}

/// Contract clause
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractClause {
    /// Clause ID
    pub id: String,
    /// Clause text
    pub text: String,
    /// Optional conditions
    pub conditions: Option<String>,
}

/// Contract party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractParty {
    /// Party's SS58 address
    pub address: String,
    /// Party's role
    pub role: String,
    /// Has signed
    pub signed: bool,
    /// Signature (if signed)
    pub signature: Option<String>,
    /// Sign timestamp
    pub signed_at: Option<u64>,
}

/// Contract status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContractStatus {
    /// Draft - not yet submitted
    Draft,
    /// Pending signatures
    Pending,
    /// All parties signed
    Active,
    /// Contract completed
    Completed,
    /// Contract disputed
    Disputed,
    /// Contract cancelled
    Cancelled,
}

/// Contract amendment proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAmendment {
    /// Amendment ID
    pub amendment_id: String,
    /// Original contract ID
    pub contract_id: String,
    /// Proposed changes
    pub changes: String,
    /// Proposer address
    pub proposer: String,
    /// Approval status by party address
    pub approvals: Vec<(String, bool)>,
    /// Created timestamp
    pub created_at: u64,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connecting via QSSH
    Connecting,
    /// QSSH handshake in progress
    Handshaking,
    /// Connected and authenticated
    Connected,
    /// QKD session established (T4+)
    QkdActive,
    /// Connection error
    Error,
}

/// QuantumHarmony RPC client with QSSH transport
pub struct QuantumHarmonyClient {
    /// Configuration
    config: QuantumHarmonyConfig,
    /// Connection state
    state: Arc<Mutex<ConnectionState>>,
    /// Request ID counter
    request_id: AtomicU64,
    /// QSSH transport (when connected)
    #[cfg(feature = "qssh")]
    qssh_client: Arc<Mutex<Option<qssh::QsshClient>>>,
    /// Fallback HTTP client
    #[cfg(feature = "native-crypto")]
    http_client: reqwest::Client,
    /// Latest block header
    latest_block: Arc<Mutex<Option<BlockHeader>>>,
}

impl QuantumHarmonyClient {
    /// Create a new QuantumHarmony client
    pub fn new(config: QuantumHarmonyConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            request_id: AtomicU64::new(1),
            #[cfg(feature = "qssh")]
            qssh_client: Arc::new(Mutex::new(None)),
            #[cfg(feature = "native-crypto")]
            http_client: reqwest::Client::new(),
            latest_block: Arc::new(Mutex::new(None)),
        }
    }

    /// Get connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.lock().await
    }

    /// Get security tier
    pub fn security_tier(&self) -> SecurityTier {
        self.config.security_tier
    }

    /// Check if QKD is active
    pub async fn is_qkd_active(&self) -> bool {
        *self.state.lock().await == ConnectionState::QkdActive
    }

    /// Connect to QuantumHarmony validator
    pub async fn connect(&self) -> Result<()> {
        *self.state.lock().await = ConnectionState::Connecting;

        // Try QSSH connection first
        #[cfg(feature = "qssh")]
        {
            match self.connect_qssh().await {
                Ok(()) => {
                    tracing::info!(
                        "Connected to QuantumHarmony via QSSH ({})",
                        self.config.qssh_endpoint
                    );
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("QSSH connection failed: {}, trying HTTP fallback", e);
                }
            }
        }

        // Fallback to HTTP
        if let Some(http_endpoint) = &self.config.http_endpoint {
            match self.connect_http(http_endpoint).await {
                Ok(()) => {
                    tracing::info!("Connected to QuantumHarmony via HTTP ({})", http_endpoint);
                    *self.state.lock().await = ConnectionState::Connected;
                    return Ok(());
                }
                Err(e) => {
                    *self.state.lock().await = ConnectionState::Error;
                    return Err(e);
                }
            }
        }

        *self.state.lock().await = ConnectionState::Error;
        Err(Error::Connection("No connection method available".into()))
    }

    /// Connect via QSSH transport
    #[cfg(feature = "qssh")]
    async fn connect_qssh(&self) -> Result<()> {
        use qssh::{QsshClient, QsshConfig, PqAlgorithm};

        *self.state.lock().await = ConnectionState::Handshaking;

        // Configure QSSH with SPHINCS+ (avoids macOS Falcon segfault)
        let qssh_config = QsshConfig {
            server: self.config.qssh_endpoint.clone(),
            username: self.config.username.clone(),
            pq_algorithm: PqAlgorithm::SphincsPlus,
            security_tier: match self.config.security_tier {
                SecurityTier::PostQuantum => qssh::SecurityTier::PostQuantum,
                SecurityTier::HardenedPQ => qssh::SecurityTier::HardenedPQ,
                SecurityTier::EntropyEnhanced => qssh::SecurityTier::EntropyEnhanced,
                SecurityTier::QuantumSecured => qssh::SecurityTier::QuantumSecured,
                SecurityTier::HybridQuantum => qssh::SecurityTier::HybridQuantum,
            },
            enable_qkd: self.config.enable_qkd,
            ..Default::default()
        };

        let client = QsshClient::connect(qssh_config).await
            .map_err(|e| Error::Connection(format!("QSSH: {}", e)))?;

        // Check if QKD is active
        let qkd_active = client.is_qkd_active();

        *self.qssh_client.lock().await = Some(client);
        *self.state.lock().await = if qkd_active {
            ConnectionState::QkdActive
        } else {
            ConnectionState::Connected
        };

        Ok(())
    }

    /// Connect via HTTP (fallback)
    #[cfg(feature = "native-crypto")]
    async fn connect_http(&self, endpoint: &str) -> Result<()> {
        // Test connection with system_chain call
        let response = self.http_client
            .post(endpoint)
            .json(&RpcRequest::new(1, "system_chain", json!([])))
            .send()
            .await
            .map_err(|e| Error::Connection(format!("HTTP: {}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::Connection(format!("HTTP error: {}", response.status())))
        }
    }

    #[cfg(not(feature = "native-crypto"))]
    async fn connect_http(&self, _endpoint: &str) -> Result<()> {
        Err(Error::Connection("HTTP client not available".into()))
    }

    /// Disconnect from validator
    pub async fn disconnect(&self) -> Result<()> {
        #[cfg(feature = "qssh")]
        {
            if let Some(client) = self.qssh_client.lock().await.take() {
                let _ = client.disconnect().await;
            }
        }
        *self.state.lock().await = ConnectionState::Disconnected;
        Ok(())
    }

    /// Make an RPC call over QSSH or HTTP
    pub async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let request = RpcRequest::new(id, method, params);

        // Try QSSH first
        #[cfg(feature = "qssh")]
        {
            if let Some(client) = self.qssh_client.lock().await.as_ref() {
                return self.rpc_over_qssh(client, &request).await;
            }
        }

        // Fallback to HTTP
        #[cfg(feature = "native-crypto")]
        if let Some(http_endpoint) = &self.config.http_endpoint {
            return self.rpc_over_http(http_endpoint, &request).await;
        }

        Err(Error::Connection("Not connected".into()))
    }

    /// RPC over QSSH transport
    #[cfg(feature = "qssh")]
    async fn rpc_over_qssh(
        &self,
        client: &qssh::QsshClient,
        request: &RpcRequest,
    ) -> Result<serde_json::Value> {
        // Serialize request
        let request_bytes = serde_json::to_vec(request)
            .map_err(|e| Error::Rpc(format!("Serialize: {}", e)))?;

        // Send over QSSH channel
        client.send(&request_bytes).await
            .map_err(|e| Error::Rpc(format!("Send: {}", e)))?;

        // Receive response
        let response_bytes = client.receive().await
            .map_err(|e| Error::Rpc(format!("Receive: {}", e)))?;

        // Parse response
        let response: RpcResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| Error::Rpc(format!("Parse: {}", e)))?;

        if let Some(error) = response.error {
            return Err(Error::Rpc(error.message));
        }

        response.result.ok_or_else(|| Error::Rpc("No result".into()))
    }

    /// RPC over HTTP transport
    #[cfg(feature = "native-crypto")]
    async fn rpc_over_http(
        &self,
        endpoint: &str,
        request: &RpcRequest,
    ) -> Result<serde_json::Value> {
        let response = self.http_client
            .post(endpoint)
            .json(request)
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

    // ==================== Notarial Pallet Methods ====================

    /// Attest a document on-chain
    pub async fn attest_document(
        &self,
        document_hash: &str,
        title: &str,
        category: DocumentCategory,
        ipfs_cid: Option<&str>,
    ) -> Result<DocumentAttestation> {
        let params = json!({
            "documentHash": document_hash,
            "title": title,
            "category": category.as_str(),
            "ipfsCid": ipfs_cid,
        });

        let result = self.rpc_call("notarial_attestDocument", params).await?;

        Ok(DocumentAttestation {
            document_hash: document_hash.to_string(),
            title: title.to_string(),
            category,
            ipfs_cid: ipfs_cid.map(String::from),
            timestamp: result["timestamp"].as_u64().unwrap_or(0),
            block_hash: result["blockHash"].as_str().map(String::from),
            attester: result["attester"].as_str().unwrap_or_default().to_string(),
        })
    }

    /// Verify a document exists on-chain
    pub async fn verify_document(&self, document_hash: &str) -> Result<Option<DocumentAttestation>> {
        let result = self.rpc_call("notarial_verifyDocument", json!([document_hash])).await?;

        if result.is_null() {
            return Ok(None);
        }

        Ok(Some(DocumentAttestation {
            document_hash: document_hash.to_string(),
            title: result["title"].as_str().unwrap_or_default().to_string(),
            category: DocumentCategory::Other, // Parse from result
            ipfs_cid: result["ipfsCid"].as_str().map(String::from),
            timestamp: result["timestamp"].as_u64().unwrap_or(0),
            block_hash: result["blockHash"].as_str().map(String::from),
            attester: result["attester"].as_str().unwrap_or_default().to_string(),
        }))
    }

    /// Add witness signature to attestation
    pub async fn witness_attestation(
        &self,
        document_hash: &str,
        witness_signature: &str,
    ) -> Result<WitnessSignature> {
        let params = json!({
            "documentHash": document_hash,
            "signature": witness_signature,
        });

        let result = self.rpc_call("notarial_witnessAttestation", params).await?;

        Ok(WitnessSignature {
            witness: result["witness"].as_str().unwrap_or_default().to_string(),
            signature: witness_signature.to_string(),
            timestamp: result["timestamp"].as_u64().unwrap_or(0),
        })
    }

    /// Get attestation witnesses
    pub async fn get_witnesses(&self, document_hash: &str) -> Result<Vec<WitnessSignature>> {
        let result = self.rpc_call("notarial_getWitnesses", json!([document_hash])).await?;

        let witnesses = result.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|w| {
                        Some(WitnessSignature {
                            witness: w["witness"].as_str()?.to_string(),
                            signature: w["signature"].as_str()?.to_string(),
                            timestamp: w["timestamp"].as_u64().unwrap_or(0),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(witnesses)
    }

    // ==================== Ricardian Contracts Pallet Methods ====================

    /// Create a new Ricardian contract
    pub async fn create_contract(
        &self,
        title: &str,
        terms: &str,
        clauses: Vec<ContractClause>,
        parties: Vec<String>,
    ) -> Result<RicardianContract> {
        let params = json!({
            "title": title,
            "terms": terms,
            "clauses": clauses,
            "parties": parties,
        });

        let result = self.rpc_call("ricardian_createContract", params).await?;

        Ok(RicardianContract {
            contract_id: result["contractId"].as_str().unwrap_or_default().to_string(),
            title: title.to_string(),
            terms: terms.to_string(),
            clauses,
            parties: parties.into_iter().map(|addr| ContractParty {
                address: addr,
                role: "Party".to_string(),
                signed: false,
                signature: None,
                signed_at: None,
            }).collect(),
            status: ContractStatus::Pending,
            created_at: result["createdAt"].as_u64().unwrap_or(0),
            ipfs_cid: result["ipfsCid"].as_str().map(String::from),
        })
    }

    /// Sign a Ricardian contract
    pub async fn sign_contract(
        &self,
        contract_id: &str,
        signature: &str,
    ) -> Result<ContractParty> {
        let params = json!({
            "contractId": contract_id,
            "signature": signature,
        });

        let result = self.rpc_call("ricardian_signContract", params).await?;

        Ok(ContractParty {
            address: result["address"].as_str().unwrap_or_default().to_string(),
            role: result["role"].as_str().unwrap_or("Party").to_string(),
            signed: true,
            signature: Some(signature.to_string()),
            signed_at: result["signedAt"].as_u64(),
        })
    }

    /// Get contract by ID
    pub async fn get_contract(&self, contract_id: &str) -> Result<Option<RicardianContract>> {
        let result = self.rpc_call("ricardian_getContract", json!([contract_id])).await?;

        if result.is_null() {
            return Ok(None);
        }

        Ok(Some(RicardianContract {
            contract_id: contract_id.to_string(),
            title: result["title"].as_str().unwrap_or_default().to_string(),
            terms: result["terms"].as_str().unwrap_or_default().to_string(),
            clauses: Vec::new(), // Parse from result
            parties: Vec::new(), // Parse from result
            status: ContractStatus::Pending, // Parse from result
            created_at: result["createdAt"].as_u64().unwrap_or(0),
            ipfs_cid: result["ipfsCid"].as_str().map(String::from),
        }))
    }

    /// Propose contract amendment
    pub async fn propose_amendment(
        &self,
        contract_id: &str,
        changes: &str,
    ) -> Result<ContractAmendment> {
        let params = json!({
            "contractId": contract_id,
            "changes": changes,
        });

        let result = self.rpc_call("ricardian_proposeAmendment", params).await?;

        Ok(ContractAmendment {
            amendment_id: result["amendmentId"].as_str().unwrap_or_default().to_string(),
            contract_id: contract_id.to_string(),
            changes: changes.to_string(),
            proposer: result["proposer"].as_str().unwrap_or_default().to_string(),
            approvals: Vec::new(),
            created_at: result["createdAt"].as_u64().unwrap_or(0),
        })
    }

    /// Approve contract amendment
    pub async fn approve_amendment(
        &self,
        amendment_id: &str,
        approval: bool,
    ) -> Result<()> {
        let params = json!({
            "amendmentId": amendment_id,
            "approval": approval,
        });

        self.rpc_call("ricardian_approveAmendment", params).await?;
        Ok(())
    }

    // ==================== Utility Methods ====================

    /// Get latest block
    pub async fn get_latest_block(&self) -> Result<BlockHeader> {
        let hash = self.rpc_call("chain_getFinalizedHead", json!([])).await?;
        let header = self.rpc_call("chain_getHeader", json!([hash])).await?;

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
            timestamp: 0,
        })
    }

    /// Get chain name
    pub async fn get_chain_name(&self) -> Result<String> {
        let result = self.rpc_call("system_chain", json!([])).await?;
        Ok(result.as_str().unwrap_or("QuantumHarmony").to_string())
    }

    /// Get node version
    pub async fn get_node_version(&self) -> Result<String> {
        let result = self.rpc_call("system_version", json!([])).await?;
        Ok(result.as_str().unwrap_or("unknown").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = QuantumHarmonyConfig::default();
        assert_eq!(config.qssh_endpoint, "localhost:42");
        assert_eq!(config.security_tier, SecurityTier::HardenedPQ);
    }

    #[test]
    fn test_document_category() {
        assert_eq!(DocumentCategory::Legal.as_str(), "Legal");
        assert_eq!(DocumentCategory::Contract.as_str(), "Contract");
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = QuantumHarmonyConfig::default();
        let client = QuantumHarmonyClient::new(config);
        assert_eq!(client.state().await, ConnectionState::Disconnected);
        assert_eq!(client.security_tier(), SecurityTier::HardenedPQ);
    }

    #[test]
    fn test_contract_status() {
        let contract = RicardianContract {
            contract_id: "test".to_string(),
            title: "Test Contract".to_string(),
            terms: "Terms here".to_string(),
            clauses: vec![],
            parties: vec![],
            status: ContractStatus::Pending,
            created_at: 0,
            ipfs_cid: None,
        };
        assert_eq!(contract.status, ContractStatus::Pending);
    }
}
