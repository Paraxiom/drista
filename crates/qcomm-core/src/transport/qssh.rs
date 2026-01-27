//! Quantum-Secure SSH (QSSH) Transport
//!
//! Direct peer-to-peer connections using post-quantum SSH.
//! Provides low-latency communication when peers can reach each other.

use super::{Transport, TransportCapability, TransportMessage, MessageMetadata};
use crate::{Error, Result};
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;

/// QSSH session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state
    New,
    /// Key exchange in progress
    KeyExchange,
    /// Authenticated and ready
    Authenticated,
    /// Session closed
    Closed,
}

/// QSSH session with a peer
pub struct QsshSession {
    /// Session ID
    pub id: String,
    /// Remote peer fingerprint
    pub peer_fingerprint: String,
    /// Remote address
    pub remote_addr: String,
    /// Session state
    pub state: SessionState,
    /// Created timestamp
    pub created_at: u64,
}

impl QsshSession {
    /// Create a new session
    pub fn new(peer_fingerprint: String, remote_addr: String) -> Self {
        Self {
            id: Self::generate_session_id(),
            peer_fingerprint,
            remote_addr,
            state: SessionState::New,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        }
    }

    fn generate_session_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..16)
            .map(|_| format!("{:02x}", rng.gen::<u8>()))
            .collect()
    }
}

/// QSSH transport configuration
#[derive(Debug, Clone)]
pub struct QsshConfig {
    /// Listen address for incoming connections
    pub listen_addr: String,
    /// Listen port
    pub listen_port: u16,
    /// Enable PQC key exchange
    pub enable_pqc: bool,
    /// Session timeout (seconds)
    pub session_timeout: u64,
}

impl Default for QsshConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".into(),
            listen_port: 2222,
            enable_pqc: true,
            session_timeout: 3600,
        }
    }
}

/// QSSH transport
pub struct QsshTransport {
    /// Configuration
    config: QsshConfig,
    /// Active sessions
    sessions: Arc<Mutex<HashMap<String, QsshSession>>>,
    /// Incoming message queue
    incoming: Arc<Mutex<VecDeque<TransportMessage>>>,
    /// Listening state
    listening: Arc<Mutex<bool>>,
}

impl QsshTransport {
    /// Create a new QSSH transport
    pub fn new(config: QsshConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            incoming: Arc::new(Mutex::new(VecDeque::new())),
            listening: Arc::new(Mutex::new(false)),
        }
    }

    /// Connect to a remote peer
    pub async fn connect_peer(&self, addr: &str, fingerprint: &str) -> Result<String> {
        let session = QsshSession::new(fingerprint.to_string(), addr.to_string());
        let session_id = session.id.clone();

        // In production:
        // 1. TCP connect
        // 2. PQ key exchange (ML-KEM)
        // 3. Authenticate with SPHINCS+ signature
        // 4. Establish encrypted channel

        tracing::info!("Connecting QSSH to {} ({})", addr, fingerprint);

        self.sessions.lock().await.insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// Disconnect a session
    pub async fn disconnect_session(&self, session_id: &str) -> Result<()> {
        if let Some(mut session) = self.sessions.lock().await.remove(session_id) {
            session.state = SessionState::Closed;
            tracing::info!("Closed QSSH session {}", session_id);
        }
        Ok(())
    }

    /// Get active sessions
    pub async fn active_sessions(&self) -> Vec<String> {
        self.sessions
            .lock()
            .await
            .iter()
            .filter(|(_, s)| s.state == SessionState::Authenticated)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Send data on a session
    async fn send_on_session(&self, session_id: &str, data: &[u8]) -> Result<()> {
        let sessions = self.sessions.lock().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| Error::Connection("Session not found".into()))?;

        if session.state != SessionState::Authenticated {
            return Err(Error::Connection("Session not authenticated".into()));
        }

        // In production, would encrypt and send over TCP
        tracing::debug!("Sending {} bytes on session {}", data.len(), session_id);

        Ok(())
    }

    /// Start listening for incoming connections
    async fn start_listener(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        tracing::info!("Starting QSSH listener on {}", addr);

        // In production, would use tokio::net::TcpListener
        // and handle incoming connections

        *self.listening.lock().await = true;
        Ok(())
    }
}

#[async_trait]
impl Transport for QsshTransport {
    fn name(&self) -> &str {
        "QSSH"
    }

    fn capabilities(&self) -> Vec<TransportCapability> {
        vec![
            TransportCapability::Send,
            TransportCapability::Receive,
            TransportCapability::PostQuantum,
        ]
    }

    async fn is_connected(&self) -> bool {
        *self.listening.lock().await || !self.sessions.lock().await.is_empty()
    }

    async fn connect(&mut self) -> Result<()> {
        self.start_listener().await
    }

    async fn disconnect(&mut self) -> Result<()> {
        *self.listening.lock().await = false;

        let session_ids: Vec<String> = self.sessions.lock().await.keys().cloned().collect();
        for id in &session_ids {
            self.disconnect_session(id).await?;
        }

        Ok(())
    }

    async fn send(&self, message: TransportMessage) -> Result<()> {
        // Find or create session for recipient
        let sessions = self.sessions.lock().await;

        let session = sessions
            .values()
            .find(|s| s.peer_fingerprint == message.to && s.state == SessionState::Authenticated);

        let session_id = match session {
            Some(s) => s.id.clone(),
            None => {
                drop(sessions);
                return Err(Error::Connection(format!(
                    "No active session for peer {}",
                    message.to
                )));
            }
        };
        drop(sessions);

        let data = bincode::serialize(&message)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        self.send_on_session(&session_id, &data).await
    }

    async fn receive(&mut self) -> Result<TransportMessage> {
        loop {
            if let Some(msg) = self.incoming.lock().await.pop_front() {
                return Ok(msg);
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            if !self.is_connected().await {
                return Err(Error::Connection("Disconnected".into()));
            }
        }
    }

    async fn poll(&mut self) -> Result<Option<TransportMessage>> {
        Ok(self.incoming.lock().await.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_qssh_transport() {
        let transport = QsshTransport::new(QsshConfig::default());
        assert!(!transport.is_connected().await);
        assert_eq!(transport.name(), "QSSH");
    }

    #[test]
    fn test_session_creation() {
        let session = QsshSession::new("fingerprint".into(), "127.0.0.1:2222".into());
        assert_eq!(session.state, SessionState::New);
        assert_eq!(session.id.len(), 32);
    }
}
