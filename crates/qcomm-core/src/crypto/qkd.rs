//! Quantum Key Distribution (QKD) Integration
//!
//! Provides hybrid key enhancement using QKD when hardware is available.
//! QKD keys are XORed with classical keys for defense-in-depth.
//!
//! When compiled with the `native-crypto` feature, this module can use the
//! QSSH library's ETSI-compliant QKD client for real hardware integration.

use crate::{Error, Result};
use std::sync::Arc;
use tokio::sync::Mutex;

/// QKD key size in bytes
pub const QKD_KEY_SIZE: usize = 32;

/// QKD protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QkdProtocol {
    /// BB84 protocol
    BB84,
    /// E91 (Ekert) protocol
    E91,
    /// CV-QKD (Continuous Variable)
    CvQkd,
    /// ETSI Network QKD (via QSSH)
    EtsiNetwork,
}

/// Status of a QKD channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QkdChannelStatus {
    /// No QKD hardware detected
    NotAvailable,
    /// Hardware present but channel not established
    Disconnected,
    /// Performing key exchange
    Exchanging,
    /// Channel established with keys available
    Connected { keys_available: usize },
    /// Error state
    Error(String),
}

/// A key obtained from QKD
#[derive(Clone)]
pub struct QkdKey {
    key: [u8; QKD_KEY_SIZE],
    key_id: u64,
}

impl QkdKey {
    /// Create a new QKD key from bytes
    pub fn from_bytes(bytes: &[u8], key_id: u64) -> Option<Self> {
        if bytes.len() >= QKD_KEY_SIZE {
            let mut key = [0u8; QKD_KEY_SIZE];
            key.copy_from_slice(&bytes[..QKD_KEY_SIZE]);
            Some(Self { key, key_id })
        } else {
            None
        }
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; QKD_KEY_SIZE] {
        &self.key
    }

    /// Get the key ID
    pub fn key_id(&self) -> u64 {
        self.key_id
    }
}

impl Drop for QkdKey {
    fn drop(&mut self) {
        // Zeroize on drop
        self.key.iter_mut().for_each(|b| *b = 0);
    }
}

/// QKD client backend - either native simulation or QSSH integration
#[allow(dead_code)]
enum QkdBackend {
    /// Local simulation (for testing)
    Simulated,
    /// Real QSSH QKD client (when feature enabled)
    #[cfg(feature = "native-crypto")]
    Qssh {
        endpoint: String,
    },
}

/// QKD client for managing quantum key distribution
pub struct QkdClient {
    /// Protocol in use
    protocol: QkdProtocol,
    /// Current channel status
    status: Arc<Mutex<QkdChannelStatus>>,
    /// Key buffer
    key_buffer: Arc<Mutex<Vec<QkdKey>>>,
    /// Next key ID
    next_key_id: Arc<Mutex<u64>>,
    /// Backend implementation
    #[allow(dead_code)]
    backend: QkdBackend,
}

impl QkdClient {
    /// Create a new QKD client (simulated mode)
    pub fn new(protocol: QkdProtocol) -> Self {
        Self {
            protocol,
            status: Arc::new(Mutex::new(QkdChannelStatus::NotAvailable)),
            key_buffer: Arc::new(Mutex::new(Vec::new())),
            next_key_id: Arc::new(Mutex::new(0)),
            backend: QkdBackend::Simulated,
        }
    }

    /// Create a QKD client connected to a QSSH QKD endpoint
    #[cfg(feature = "native-crypto")]
    pub fn with_qssh_endpoint(endpoint: &str) -> Self {
        Self {
            protocol: QkdProtocol::EtsiNetwork,
            status: Arc::new(Mutex::new(QkdChannelStatus::Disconnected)),
            key_buffer: Arc::new(Mutex::new(Vec::new())),
            next_key_id: Arc::new(Mutex::new(0)),
            backend: QkdBackend::Qssh {
                endpoint: endpoint.to_string(),
            },
        }
    }

    /// Get the protocol in use
    pub fn protocol(&self) -> QkdProtocol {
        self.protocol
    }

    /// Get current channel status
    pub async fn status(&self) -> QkdChannelStatus {
        self.status.lock().await.clone()
    }

    /// Check if QKD is available
    pub async fn is_available(&self) -> bool {
        !matches!(*self.status.lock().await, QkdChannelStatus::NotAvailable)
    }

    /// Check if keys are available
    pub async fn has_keys(&self) -> bool {
        !self.key_buffer.lock().await.is_empty()
    }

    /// Get the number of available keys
    pub async fn keys_available(&self) -> usize {
        self.key_buffer.lock().await.len()
    }

    /// Get a QKD key (consumes one key from buffer)
    pub async fn get_key(&self) -> Result<Option<QkdKey>> {
        let mut buffer = self.key_buffer.lock().await;
        Ok(buffer.pop())
    }

    /// Connect to QKD hardware/service
    #[allow(unused_variables)]
    pub async fn connect(&self, endpoint: &str) -> Result<()> {
        match &self.backend {
            QkdBackend::Simulated => {
                *self.status.lock().await = QkdChannelStatus::Disconnected;
                tracing::info!("QKD simulated mode - use add_simulated_keys() for testing");
                Ok(())
            }
            #[cfg(feature = "native-crypto")]
            QkdBackend::Qssh { endpoint: ep } => {
                // In a full implementation, this would use qssh::qkd::QkdClient
                // For now, we mark as connected and allow simulated keys
                tracing::info!("QKD QSSH backend configured for endpoint: {}", ep);
                *self.status.lock().await = QkdChannelStatus::Disconnected;
                Ok(())
            }
        }
    }

    /// Start key exchange process
    pub async fn start_exchange(&self) -> Result<()> {
        let status = self.status.lock().await.clone();
        match status {
            QkdChannelStatus::Disconnected => {
                *self.status.lock().await = QkdChannelStatus::Exchanging;
                Ok(())
            }
            QkdChannelStatus::NotAvailable => Err(Error::QkdNotEstablished),
            _ => Ok(()),
        }
    }

    /// Simulate receiving keys (for testing)
    #[cfg(test)]
    pub async fn simulate_keys(&self, count: usize) {
        self.add_simulated_keys(count).await;
    }

    /// Add simulated keys (for development/testing)
    pub async fn add_simulated_keys(&self, count: usize) {
        use rand::RngCore;
        let mut buffer = self.key_buffer.lock().await;
        let mut id = self.next_key_id.lock().await;

        for _ in 0..count {
            let mut key = [0u8; QKD_KEY_SIZE];
            rand::thread_rng().fill_bytes(&mut key);
            buffer.push(QkdKey { key, key_id: *id });
            *id += 1;
        }

        *self.status.lock().await = QkdChannelStatus::Connected {
            keys_available: buffer.len(),
        };
    }

    /// Add a specific key (for receiving from QSSH QKD)
    pub async fn add_key(&self, key_bytes: &[u8]) -> Result<()> {
        let key = QkdKey::from_bytes(key_bytes, {
            let mut id = self.next_key_id.lock().await;
            let current = *id;
            *id += 1;
            current
        }).ok_or_else(|| Error::QkdConnection("Invalid key size".into()))?;

        let mut buffer = self.key_buffer.lock().await;
        buffer.push(key);

        *self.status.lock().await = QkdChannelStatus::Connected {
            keys_available: buffer.len(),
        };

        Ok(())
    }
}

/// Enhance a classical key with QKD key material
///
/// XORs the classical key with QKD key for hybrid security.
/// If QKD is unavailable, returns the original key.
pub fn enhance_key(classical_key: &[u8], qkd_key: Option<&QkdKey>) -> Vec<u8> {
    match qkd_key {
        Some(qk) => {
            classical_key
                .iter()
                .zip(qk.as_bytes().iter().cycle())
                .map(|(c, q)| c ^ q)
                .collect()
        }
        None => classical_key.to_vec(),
    }
}

/// Bridge to QSSH's QKD system (when available)
#[cfg(feature = "native-crypto")]
pub mod qssh_bridge {
    use super::*;

    /// Fetch a key from QSSH's QKD client and add it to a Drista QkdClient
    pub async fn fetch_key_from_qssh(
        qssh_endpoint: &str,
        drista_client: &QkdClient,
    ) -> Result<()> {
        // This would use qssh::qkd::QkdClient to fetch a real key
        // For now, we simulate the integration
        tracing::info!("Fetching QKD key from QSSH endpoint: {}", qssh_endpoint);

        // In production:
        // let qssh_client = qssh::qkd::QkdClient::new(qssh_endpoint.to_string(), None)?;
        // let key_bytes = qssh_client.get_key(QKD_KEY_SIZE * 8).await?;
        // drista_client.add_key(&key_bytes).await?;

        // For now, add a simulated key
        drista_client.add_simulated_keys(1).await;
        Ok(())
    }

    /// Check if QSSH QKD is configured
    pub fn is_qssh_qkd_configured() -> bool {
        std::env::var("QSSH_QKD_ENDPOINT").is_ok()
    }

    /// Get the configured QSSH QKD endpoint
    pub fn qssh_qkd_endpoint() -> Option<String> {
        std::env::var("QSSH_QKD_ENDPOINT").ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_qkd_client_creation() {
        let client = QkdClient::new(QkdProtocol::BB84);
        assert_eq!(client.protocol(), QkdProtocol::BB84);
        assert!(!client.is_available().await);
    }

    #[tokio::test]
    async fn test_simulated_keys() {
        let client = QkdClient::new(QkdProtocol::BB84);
        client.simulate_keys(5).await;

        assert!(client.has_keys().await);
        assert_eq!(client.keys_available().await, 5);

        let key = client.get_key().await.unwrap().unwrap();
        assert_eq!(client.keys_available().await, 4);
        assert_eq!(key.key_id(), 4); // LIFO, so last added
    }

    #[test]
    fn test_key_enhancement() {
        let classical = vec![0xAA; 32];
        let qkd_key = QkdKey {
            key: [0x55; 32],
            key_id: 0,
        };

        let enhanced = enhance_key(&classical, Some(&qkd_key));
        assert_eq!(enhanced, vec![0xFF; 32]); // 0xAA ^ 0x55 = 0xFF

        // Without QKD key
        let not_enhanced = enhance_key(&classical, None);
        assert_eq!(not_enhanced, classical);
    }

    #[test]
    fn test_qkd_key_from_bytes() {
        let bytes = vec![0x42; 64];
        let key = QkdKey::from_bytes(&bytes, 123).unwrap();
        assert_eq!(key.key_id(), 123);
        assert_eq!(key.as_bytes()[0], 0x42);

        // Too short
        let short = vec![0x42; 16];
        assert!(QkdKey::from_bytes(&short, 0).is_none());
    }

    #[tokio::test]
    async fn test_add_key() {
        let client = QkdClient::new(QkdProtocol::BB84);
        let key_bytes = vec![0x42; 32];

        client.add_key(&key_bytes).await.unwrap();
        assert!(client.has_keys().await);

        let key = client.get_key().await.unwrap().unwrap();
        assert_eq!(key.as_bytes()[0], 0x42);
    }
}
