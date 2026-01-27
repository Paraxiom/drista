//! Quantum Key Distribution (QKD) Integration
//!
//! Provides hybrid key enhancement using QKD when hardware is available.
//! QKD keys are XORed with classical keys for defense-in-depth.

use crate::{Error, Result};
use std::sync::Arc;
use tokio::sync::Mutex;

/// QKD key size in bytes
const QKD_KEY_SIZE: usize = 32;

/// QKD protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QkdProtocol {
    /// BB84 protocol
    BB84,
    /// E91 (Ekert) protocol
    E91,
    /// CV-QKD (Continuous Variable)
    CvQkd,
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
}

impl QkdClient {
    /// Create a new QKD client
    pub fn new(protocol: QkdProtocol) -> Self {
        Self {
            protocol,
            status: Arc::new(Mutex::new(QkdChannelStatus::NotAvailable)),
            key_buffer: Arc::new(Mutex::new(Vec::new())),
            next_key_id: Arc::new(Mutex::new(0)),
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
    pub async fn connect(&self, _endpoint: &str) -> Result<()> {
        // In production, this would:
        // 1. Connect to QKD hardware or QKD-as-a-Service
        // 2. Perform quantum channel calibration
        // 3. Begin key exchange
        *self.status.lock().await = QkdChannelStatus::Disconnected;
        Err(Error::QkdNotEstablished)
    }

    /// Start key exchange process
    pub async fn start_exchange(&self) -> Result<()> {
        let status = self.status.lock().await.clone();
        match status {
            QkdChannelStatus::Disconnected => {
                *self.status.lock().await = QkdChannelStatus::Exchanging;
                // In production, would start BB84/E91/CV-QKD protocol
                Ok(())
            }
            QkdChannelStatus::NotAvailable => Err(Error::QkdNotEstablished),
            _ => Ok(()),
        }
    }

    /// Simulate receiving keys (for testing)
    #[cfg(test)]
    pub async fn simulate_keys(&self, count: usize) {
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
}
