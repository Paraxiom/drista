//! BLE Mesh Transport with Post-Quantum Encryption (BitChat Compatible)
//!
//! Implements Bluetooth Low Energy mesh networking for peer-to-peer
//! communication without internet connectivity.
//!
//! ## PQC Integration
//! - Key exchange: ML-KEM-1024 (NIST FIPS 203)
//! - Message encryption: AES-256-GCM
//! - Key derivation: HKDF-SHA256
//! - Signatures: SPHINCS+ (optional)
//!
//! ## Protocol Flow
//! ```text
//! Alice                              Bob
//!   |                                  |
//!   |-- BLE Advertise (EK) ----------->|
//!   |<- BLE Advertise (EK) ------------|
//!   |                                  |
//!   |-- Encapsulate(Bob_EK) ---------> |
//!   |   -> KEM_CT + encrypted msg      |
//!   |                                  |
//!   |                   Decapsulate ---|
//!   |                   Decrypt msg    |
//! ```

use super::{Transport, TransportCapability, TransportMessage};
use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(feature = "native-crypto")]
use crate::crypto::{MlKemKeyPair, MlKemPublicKey, MlKemCiphertext, aead};

use hkdf::Hkdf;
use sha2::Sha256;

/// BLE service UUID for BitChat compatibility
pub const BITCHAT_SERVICE_UUID: &str = "00001800-0000-1000-8000-00805f9b34fb";

/// BLE characteristic UUID for messages
pub const MESSAGE_CHARACTERISTIC_UUID: &str = "00002a00-0000-1000-8000-00805f9b34fb";

/// BLE characteristic UUID for PQ key exchange
pub const PQ_KEY_CHARACTERISTIC_UUID: &str = "00002a01-0000-1000-8000-00805f9b34fb";

/// Maximum BLE message size (MTU limitation)
pub const MAX_BLE_MESSAGE_SIZE: usize = 512;

/// Maximum hops for mesh routing
pub const MAX_HOP_COUNT: u8 = 10;

/// Default TTL for messages
pub const DEFAULT_TTL: u8 = 5;

/// ML-KEM-1024 ciphertext size
const MLKEM_CIPHERTEXT_SIZE: usize = 1568;

/// AES-GCM nonce size
const NONCE_SIZE: usize = 12;

/// HKDF info string for BLE PQ sessions
const HKDF_INFO_BLE: &[u8] = b"drista-ble-pq-v1";

/// BLE packet type for protocol identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlePacketType {
    /// Key exchange announcement (contains ML-KEM public key)
    KeyAnnounce = 0x01,
    /// PQ-encrypted message
    PqMessage = 0x02,
    /// Legacy message (for BitChat interop)
    LegacyMessage = 0x03,
    /// Acknowledgement
    Ack = 0x04,
    /// Mesh routing packet
    MeshRelay = 0x05,
}

/// BLE peer information with PQC support
#[derive(Debug, Clone)]
pub struct BlePeer {
    /// Device address
    pub address: String,
    /// Device name (if advertised)
    pub name: Option<String>,
    /// Signal strength (RSSI)
    pub rssi: i16,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Supports PQC
    pub supports_pqc: bool,
    /// Peer's ML-KEM encapsulation key (if PQC supported)
    pub mlkem_ek: Option<Vec<u8>>,
}

/// PQ session state with a peer
#[derive(Clone)]
pub struct PqBleSession {
    /// Peer address
    pub peer_address: String,
    /// Derived AES key (from ML-KEM shared secret via HKDF)
    pub aes_key: [u8; 32],
    /// Message counter (for replay protection)
    pub send_counter: u64,
    /// Receive counter
    pub recv_counter: u64,
    /// Session established timestamp
    pub established_at: u64,
}

/// BLE mesh packet format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlePacket {
    /// Packet type
    pub packet_type: u8,
    /// Sender address
    pub from: String,
    /// Recipient address (or broadcast)
    pub to: String,
    /// Hop count
    pub hop_count: u8,
    /// TTL
    pub ttl: u8,
    /// Message ID (for deduplication)
    pub msg_id: [u8; 8],
    /// Payload
    pub payload: Vec<u8>,
}

/// PQ-encrypted message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqBlePayload {
    /// ML-KEM ciphertext (for ephemeral key exchange)
    pub kem_ct: Vec<u8>,
    /// AES-GCM nonce
    pub nonce: [u8; NONCE_SIZE],
    /// AES-GCM ciphertext (message + tag)
    pub ciphertext: Vec<u8>,
    /// Message counter (for replay protection)
    pub counter: u64,
}

/// BLE mesh transport with PQC encryption
pub struct BleTransport {
    /// Connected state
    connected: bool,
    /// Our ML-KEM keypair
    #[cfg(feature = "native-crypto")]
    mlkem_keypair: Option<MlKemKeyPair>,
    /// Known peers
    peers: Arc<Mutex<HashMap<String, BlePeer>>>,
    /// Active PQ sessions
    sessions: Arc<Mutex<HashMap<String, PqBleSession>>>,
    /// Message queue
    incoming: Arc<Mutex<VecDeque<TransportMessage>>>,
    /// Pending outgoing messages
    outgoing: Arc<Mutex<VecDeque<BlePacket>>>,
    /// Our device address
    device_address: String,
    /// Seen message IDs (for deduplication)
    seen_messages: Arc<Mutex<VecDeque<[u8; 8]>>>,
}

impl BleTransport {
    /// Create a new BLE transport with PQC support
    #[cfg(feature = "native-crypto")]
    pub fn new() -> Result<Self> {
        // Generate ML-KEM keypair for this device
        let mlkem_keypair = MlKemKeyPair::generate()?;

        Ok(Self {
            connected: false,
            mlkem_keypair: Some(mlkem_keypair),
            peers: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            incoming: Arc::new(Mutex::new(VecDeque::new())),
            outgoing: Arc::new(Mutex::new(VecDeque::new())),
            device_address: Self::generate_device_address(),
            seen_messages: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
        })
    }

    /// Create without PQC (for non-native builds)
    #[cfg(not(feature = "native-crypto"))]
    pub fn new() -> Result<Self> {
        Ok(Self {
            connected: false,
            peers: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            incoming: Arc::new(Mutex::new(VecDeque::new())),
            outgoing: Arc::new(Mutex::new(VecDeque::new())),
            device_address: Self::generate_device_address(),
            seen_messages: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
        })
    }

    /// Generate a random device address
    fn generate_device_address() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>()
        )
    }

    /// Get our ML-KEM public key for advertisement
    #[cfg(feature = "native-crypto")]
    pub fn public_key(&self) -> Option<&[u8]> {
        self.mlkem_keypair.as_ref().map(|kp| kp.public_key().as_bytes())
    }

    /// Get known peers
    pub async fn peers(&self) -> Vec<BlePeer> {
        self.peers.lock().await.values().cloned().collect()
    }

    /// Register a discovered peer
    pub async fn register_peer(&self, peer: BlePeer) {
        let mut peers = self.peers.lock().await;
        peers.insert(peer.address.clone(), peer);
    }

    /// Derive AES key from ML-KEM shared secret using HKDF
    fn derive_aes_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut aes_key = [0u8; 32];
        hk.expand(HKDF_INFO_BLE, &mut aes_key)
            .map_err(|_| Error::KeyExchange("HKDF expansion failed".into()))?;
        Ok(aes_key)
    }

    /// Encrypt a message for a peer using ML-KEM + AES-256-GCM
    #[cfg(feature = "native-crypto")]
    pub async fn encrypt_for_peer(&self, peer_address: &str, plaintext: &[u8]) -> Result<PqBlePayload> {
        let peers = self.peers.lock().await;
        let peer = peers.get(peer_address)
            .ok_or_else(|| Error::Ble(format!("Unknown peer: {}", peer_address)))?;

        let peer_ek = peer.mlkem_ek.as_ref()
            .ok_or_else(|| Error::Ble("Peer does not support PQC".into()))?;

        // Parse peer's encapsulation key
        let peer_pk = MlKemPublicKey::from_bytes(peer_ek)?;

        // Encapsulate to get shared secret + ciphertext
        let (kem_ct, shared_secret) = peer_pk.encapsulate()?;

        // Derive AES key from shared secret
        let aes_key = Self::derive_aes_key(shared_secret.as_bytes())?;

        // Get or increment session counter
        let counter = {
            let mut sessions = self.sessions.lock().await;
            let session = sessions.entry(peer_address.to_string()).or_insert_with(|| {
                PqBleSession {
                    peer_address: peer_address.to_string(),
                    aes_key,
                    send_counter: 0,
                    recv_counter: 0,
                    established_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                }
            });
            session.send_counter += 1;
            session.send_counter
        };

        // Build associated data (for AEAD)
        let ad = format!("{}:{}:{}", self.device_address, peer_address, counter);

        // Encrypt with AES-256-GCM
        let ciphertext_with_nonce = aead::encrypt(plaintext, &aes_key, ad.as_bytes())?;

        // Split nonce from ciphertext
        let nonce: [u8; NONCE_SIZE] = ciphertext_with_nonce[..NONCE_SIZE].try_into()
            .map_err(|_| Error::Encryption("Invalid nonce".into()))?;
        let ciphertext = ciphertext_with_nonce[NONCE_SIZE..].to_vec();

        Ok(PqBlePayload {
            kem_ct: kem_ct.as_bytes().to_vec(),
            nonce,
            ciphertext,
            counter,
        })
    }

    /// Decrypt a message from a peer using ML-KEM + AES-256-GCM
    #[cfg(feature = "native-crypto")]
    pub async fn decrypt_from_peer(&self, sender_address: &str, payload: &PqBlePayload) -> Result<Vec<u8>> {
        let keypair = self.mlkem_keypair.as_ref()
            .ok_or_else(|| Error::Ble("No ML-KEM keypair".into()))?;

        // Parse KEM ciphertext
        let kem_ct = MlKemCiphertext::from_bytes(&payload.kem_ct)?;

        // Decapsulate to get shared secret
        let shared_secret = keypair.decapsulate(&kem_ct)?;

        // Derive AES key
        let aes_key = Self::derive_aes_key(shared_secret.as_bytes())?;

        // Check counter for replay protection
        {
            let mut sessions = self.sessions.lock().await;
            if let Some(session) = sessions.get_mut(sender_address) {
                if payload.counter <= session.recv_counter {
                    return Err(Error::Ble("Replay attack detected".into()));
                }
                session.recv_counter = payload.counter;
            }
        }

        // Build associated data
        let ad = format!("{}:{}:{}", sender_address, self.device_address, payload.counter);

        // Reconstruct ciphertext with nonce
        let mut ciphertext_with_nonce = Vec::with_capacity(NONCE_SIZE + payload.ciphertext.len());
        ciphertext_with_nonce.extend_from_slice(&payload.nonce);
        ciphertext_with_nonce.extend_from_slice(&payload.ciphertext);

        // Decrypt
        aead::decrypt(&ciphertext_with_nonce, &aes_key, ad.as_bytes())
    }

    /// Start BLE scanning for peers
    pub async fn start_scanning(&self) -> Result<()> {
        if !self.connected {
            return Err(Error::Ble("Not connected".into()));
        }

        #[cfg(feature = "ble")]
        {
            // In production, would use btleplug for actual scanning
            tracing::info!("Started BLE scanning for BitChat/Drista peers");
        }

        Ok(())
    }

    /// Stop BLE scanning
    pub async fn stop_scanning(&self) -> Result<()> {
        tracing::info!("Stopped BLE scanning");
        Ok(())
    }

    /// Start advertising as a Drista peer with PQ capability
    #[cfg(feature = "native-crypto")]
    pub async fn start_advertising(&self) -> Result<()> {
        if !self.connected {
            return Err(Error::Ble("Not connected".into()));
        }

        // In production, would set up GATT server with:
        // - BITCHAT_SERVICE_UUID
        // - PQ_KEY_CHARACTERISTIC_UUID containing our ML-KEM public key

        if let Some(pk) = self.public_key() {
            tracing::info!(
                "Started BLE advertising with PQC support, EK size: {} bytes",
                pk.len()
            );
        }

        Ok(())
    }

    /// Create a BLE packet for sending
    fn create_packet(&self, packet_type: BlePacketType, to: &str, payload: Vec<u8>) -> BlePacket {
        use rand::RngCore;
        let mut msg_id = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut msg_id);

        BlePacket {
            packet_type: packet_type as u8,
            from: self.device_address.clone(),
            to: to.to_string(),
            hop_count: 0,
            ttl: DEFAULT_TTL,
            msg_id,
            payload,
        }
    }

    /// Check if we've seen this message before
    async fn is_duplicate(&self, msg_id: &[u8; 8]) -> bool {
        let seen = self.seen_messages.lock().await;
        seen.contains(msg_id)
    }

    /// Mark message as seen
    async fn mark_seen(&self, msg_id: [u8; 8]) {
        let mut seen = self.seen_messages.lock().await;
        seen.push_back(msg_id);
        // Keep only last 1000 messages
        while seen.len() > 1000 {
            seen.pop_front();
        }
    }

    /// Route message through mesh
    async fn route_message(&self, packet: &BlePacket) -> Result<()> {
        // Check TTL
        if packet.hop_count >= MAX_HOP_COUNT || packet.ttl == 0 {
            return Err(Error::Ble("Message TTL expired".into()));
        }

        // Check for duplicates
        if self.is_duplicate(&packet.msg_id).await {
            return Ok(()); // Already processed
        }
        self.mark_seen(packet.msg_id).await;

        let peers = self.peers.lock().await;
        if peers.is_empty() {
            return Err(Error::Ble("No peers available".into()));
        }

        // Queue for transmission (flooding)
        let mut outgoing = self.outgoing.lock().await;
        let mut forwarded = packet.clone();
        forwarded.hop_count += 1;
        forwarded.ttl -= 1;
        outgoing.push_back(forwarded);

        Ok(())
    }

    /// Chunk message for BLE MTU
    pub fn chunk_message(data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(MAX_BLE_MESSAGE_SIZE)
            .map(|c| c.to_vec())
            .collect()
    }

    /// Reassemble chunked message
    pub fn reassemble_message(chunks: &[Vec<u8>]) -> Vec<u8> {
        chunks.iter().flatten().copied().collect()
    }
}

impl Default for BleTransport {
    fn default() -> Self {
        Self::new().expect("Failed to create BLE transport")
    }
}

#[async_trait]
impl Transport for BleTransport {
    fn name(&self) -> &str {
        "BLE Mesh (PQC)"
    }

    fn capabilities(&self) -> Vec<TransportCapability> {
        vec![
            TransportCapability::Send,
            TransportCapability::Receive,
            TransportCapability::PostQuantum,
            TransportCapability::OfflineDelivery,
        ]
    }

    async fn is_connected(&self) -> bool {
        self.connected
    }

    async fn connect(&mut self) -> Result<()> {
        #[cfg(feature = "ble")]
        {
            use btleplug::api::{Central, Manager as _};
            use btleplug::platform::Manager;

            let manager = Manager::new().await
                .map_err(|e| Error::Ble(e.to_string()))?;

            let adapters = manager.adapters().await
                .map_err(|e| Error::Ble(e.to_string()))?;

            if adapters.is_empty() {
                return Err(Error::Ble("No BLE adapters found".into()));
            }

            let adapter = &adapters[0];
            adapter.start_scan(btleplug::api::ScanFilter::default()).await
                .map_err(|e| Error::Ble(e.to_string()))?;
        }

        self.connected = true;

        #[cfg(feature = "native-crypto")]
        if let Some(pk) = self.public_key() {
            tracing::info!(
                "BLE transport connected with ML-KEM-1024 support, EK: {} bytes",
                pk.len()
            );
        }

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        tracing::info!("BLE transport disconnected");
        Ok(())
    }

    #[cfg(feature = "native-crypto")]
    async fn send(&self, message: TransportMessage) -> Result<()> {
        if !self.connected {
            return Err(Error::Ble("Not connected".into()));
        }

        // Encrypt payload for recipient
        let encrypted = self.encrypt_for_peer(&message.to, &message.payload).await?;

        // Serialize encrypted payload
        let payload = bincode::serialize(&encrypted)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Check size
        if payload.len() > MAX_BLE_MESSAGE_SIZE * 10 {
            return Err(Error::Ble("Message too large for BLE".into()));
        }

        // Create packet
        let packet = self.create_packet(BlePacketType::PqMessage, &message.to, payload);

        // Route through mesh
        self.route_message(&packet).await?;

        tracing::debug!(
            "Sent PQ-encrypted BLE message to {}, size: {} bytes",
            message.to,
            packet.payload.len()
        );

        Ok(())
    }

    #[cfg(not(feature = "native-crypto"))]
    async fn send(&self, message: TransportMessage) -> Result<()> {
        if !self.connected {
            return Err(Error::Ble("Not connected".into()));
        }

        // Non-PQC fallback
        let payload = bincode::serialize(&message)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        let packet = self.create_packet(BlePacketType::LegacyMessage, &message.to, payload);
        self.route_message(&packet).await?;

        Ok(())
    }

    async fn receive(&mut self) -> Result<TransportMessage> {
        loop {
            if let Some(msg) = self.incoming.lock().await.pop_front() {
                return Ok(msg);
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            if !self.connected {
                return Err(Error::Ble("Disconnected while waiting".into()));
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
    async fn test_ble_transport_creation() {
        let transport = BleTransport::new().unwrap();
        assert!(!transport.is_connected().await);
        assert_eq!(transport.name(), "BLE Mesh (PQC)");
    }

    #[tokio::test]
    async fn test_chunk_message() {
        let data = vec![0u8; 1500];
        let chunks = BleTransport::chunk_message(&data);
        assert_eq!(chunks.len(), 3); // 512 + 512 + 476

        let reassembled = BleTransport::reassemble_message(&chunks);
        assert_eq!(reassembled, data);
    }

    #[cfg(feature = "native-crypto")]
    #[tokio::test]
    async fn test_pq_encryption_roundtrip() {
        // Create two transports (simulating two devices)
        let mut alice = BleTransport::new().unwrap();
        let mut bob = BleTransport::new().unwrap();

        // Set known addresses for testing
        alice.device_address = "ALICE:01:02:03:04:05".to_string();
        bob.device_address = "BOB:01:02:03:04:05".to_string();

        // Get Bob's public key
        let bob_pk = bob.public_key().unwrap().to_vec();

        // Register Bob as a peer with Alice (using Bob's actual address)
        alice.register_peer(BlePeer {
            address: bob.device_address.clone(),
            name: Some("Bob".to_string()),
            rssi: -50,
            last_seen: 0,
            supports_pqc: true,
            mlkem_ek: Some(bob_pk),
        }).await;

        // Alice encrypts a message for Bob
        let plaintext = b"Hello Bob, this is PQ-encrypted!";
        let encrypted = alice.encrypt_for_peer(&bob.device_address, plaintext).await.unwrap();

        // Verify KEM ciphertext size
        assert_eq!(encrypted.kem_ct.len(), MLKEM_CIPHERTEXT_SIZE);

        // Bob decrypts
        // Note: In real scenario, Bob would receive the packet and decrypt
        // For this test, we manually call decrypt
        let decrypted = bob.decrypt_from_peer(&alice.device_address, &encrypted).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_deduplication() {
        let transport = BleTransport::new().unwrap();
        let msg_id = [1u8; 8];

        assert!(!transport.is_duplicate(&msg_id).await);
        transport.mark_seen(msg_id).await;
        assert!(transport.is_duplicate(&msg_id).await);
    }

    #[test]
    fn test_hkdf_derivation() {
        let shared_secret = [42u8; 32];
        let key1 = BleTransport::derive_aes_key(&shared_secret).unwrap();
        let key2 = BleTransport::derive_aes_key(&shared_secret).unwrap();

        // Same input should produce same output
        assert_eq!(key1, key2);

        // Different input should produce different output
        let different_secret = [43u8; 32];
        let key3 = BleTransport::derive_aes_key(&different_secret).unwrap();
        assert_ne!(key1, key3);
    }
}
