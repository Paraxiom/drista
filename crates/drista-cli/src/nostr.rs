//! Nostr protocol implementation with NIP-04 encrypted DMs
//!
//! Implements two encryption protocols:
//! - NIP-04 (Kind 4): ECDH + AES-256-CBC (legacy, for interop)
//! - PQ-DM (Kind 20004): ML-KEM-1024 + AES-256-GCM (post-quantum)

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::{SinkExt, StreamExt};
use secp256k1::{ecdh::SharedSecret, Keypair, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{debug, info, warn};

// AES-256-CBC types for NIP-04
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// NIP-04 encrypted DM kind (legacy, classical crypto)
pub const KIND_ENCRYPTED_DM: u16 = 4;

/// PQ-DM kind (post-quantum, ML-KEM-1024 + AES-256-GCM)
pub const KIND_PQ_ENCRYPTED_DM: u16 = 20004;

/// PQ public key publication kind (for discovery)
#[allow(dead_code)]
pub const KIND_PQ_PUBKEY: u16 = 30078;

/// Default relays - matches web app and production validators
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",           // Public relay (fallback)
    "wss://drista.paraxiom.org/ws",   // Alice (Montreal)
    "wss://nos.lol",                  // Public relay (fallback)
];

/// Nostr event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrEvent {
    /// Compute event ID per NIP-01
    pub fn compute_id(&mut self) {
        let serialized = serde_json::json!([
            0,
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content
        ]);

        let hash = Sha256::digest(serialized.to_string().as_bytes());
        self.id = hex::encode(hash);
    }

    /// Sign event with Schnorr signature per NIP-01
    pub fn sign(&mut self, keypair: &Keypair) {
        let secp = Secp256k1::new();
        let id_bytes = hex::decode(&self.id).expect("valid id");
        let msg = secp256k1::Message::from_digest_slice(&id_bytes).expect("32 bytes");
        let sig = secp.sign_schnorr(&msg, keypair);
        self.sig = hex::encode(sig.serialize());
    }
}

/// Relay message types
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RelayMessage {
    Event { event: NostrEvent },
    Notice(String, String),
    Eose(String, String),
    Ok(String, String, bool, String),
}

/// Nostr client with WebSocket connection
pub struct NostrClient {
    keypair: Keypair,
    pubkey_hex: String,
    secret_key: SecretKey,
    ws_write: Arc<Mutex<futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        WsMessage,
    >>>,
    ws_read: Arc<Mutex<futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    >>>,
    #[allow(dead_code)]
    relay_url: String,
}

impl NostrClient {
    /// Create a new Nostr client and connect to relay
    pub async fn new(private_key_hex: &str, relay_url: &str) -> Result<Self> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&hex::decode(private_key_hex)?)?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly, _) = keypair.x_only_public_key();
        let pubkey_hex = hex::encode(xonly.serialize());

        info!("Connecting to relay: {}", relay_url);

        let (ws_stream, _) = connect_async(relay_url)
            .await
            .context("Failed to connect to relay")?;

        let (write, read) = ws_stream.split();

        info!("Connected to {}", relay_url);

        Ok(Self {
            keypair,
            pubkey_hex,
            secret_key,
            ws_write: Arc::new(Mutex::new(write)),
            ws_read: Arc::new(Mutex::new(read)),
            relay_url: relay_url.to_string(),
        })
    }

    /// Get our public key
    #[allow(dead_code)]
    pub fn pubkey(&self) -> &str {
        &self.pubkey_hex
    }

    /// Subscribe to DMs sent to us
    pub async fn subscribe_dms(&mut self) -> Result<()> {
        let sub_id = format!("drista_{}", rand::random::<u32>());

        let req = serde_json::json!([
            "REQ",
            &sub_id,
            {
                "#p": [&self.pubkey_hex],
                "kinds": [KIND_ENCRYPTED_DM, KIND_PQ_ENCRYPTED_DM],
                "since": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs() - 3600  // Last hour
            }
        ]);

        let msg = WsMessage::Text(req.to_string().into());
        self.ws_write.lock().await.send(msg).await?;

        info!("Subscribed to DMs with ID: {}", sub_id);
        Ok(())
    }

    /// Send an encrypted DM (NIP-04)
    pub async fn send_dm(&self, to_pubkey: &str, plaintext: &str) -> Result<()> {
        // Compute shared secret via ECDH
        let recipient_pubkey = parse_pubkey(to_pubkey)?;
        let shared_secret = self.compute_shared_secret(&recipient_pubkey);

        // Encrypt content with NIP-04 (AES-256-CBC)
        let encrypted = encrypt_nip04(plaintext, &shared_secret)?;

        // Create event
        let mut event = NostrEvent {
            id: String::new(),
            pubkey: self.pubkey_hex.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            kind: KIND_ENCRYPTED_DM,
            tags: vec![vec!["p".to_string(), to_pubkey.to_string()]],
            content: encrypted,
            sig: String::new(),
        };

        event.compute_id();
        event.sign(&self.keypair);

        // Send to relay
        let msg = serde_json::json!(["EVENT", event]);
        self.ws_write
            .lock()
            .await
            .send(WsMessage::Text(msg.to_string().into()))
            .await?;

        debug!("Sent NIP-04 DM to {}", &to_pubkey[..16]);
        Ok(())
    }

    /// Decrypt a received DM
    pub fn decrypt_dm(&self, event: &NostrEvent) -> Result<String> {
        let sender_pubkey = parse_pubkey(&event.pubkey)?;
        let shared_secret = self.compute_shared_secret(&sender_pubkey);
        decrypt_nip04(&event.content, &shared_secret)
    }

    /// Send a PQ-encrypted DM (Kind 20004)
    pub async fn send_pq_dm(
        &self,
        to_nostr_pubkey: &str,
        encrypted_content: &str,
        our_pq_pubkey: &str,
    ) -> Result<()> {
        // Create Kind 20004 event with PQ-encrypted content
        let mut event = NostrEvent {
            id: String::new(),
            pubkey: self.pubkey_hex.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            kind: KIND_PQ_ENCRYPTED_DM,
            tags: vec![
                vec!["p".to_string(), to_nostr_pubkey.to_string()],
                vec!["pq".to_string(), our_pq_pubkey.to_string()], // Include our PQ pubkey for replies
            ],
            content: encrypted_content.to_string(),
            sig: String::new(),
        };

        event.compute_id();
        event.sign(&self.keypair);

        // Send to relay
        let msg = serde_json::json!(["EVENT", event]);
        self.ws_write
            .lock()
            .await
            .send(WsMessage::Text(msg.to_string().into()))
            .await?;

        debug!("Sent PQ-DM (Kind 20004) to {}", &to_nostr_pubkey[..16]);
        Ok(())
    }

    /// Receive next message from relay
    pub async fn receive(&mut self) -> Result<Option<NostrEvent>> {
        let msg = {
            let mut read = self.ws_read.lock().await;
            match tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                read.next(),
            )
            .await
            {
                Ok(Some(Ok(WsMessage::Text(text)))) => Some(text),
                Ok(Some(Ok(_))) => None, // Non-text message
                Ok(Some(Err(e))) => return Err(anyhow!("WebSocket error: {}", e)),
                Ok(None) => return Err(anyhow!("Connection closed")),
                Err(_) => None, // Timeout, no message
            }
        };

        if let Some(text) = msg {
            // Parse relay message
            if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                if arr.len() >= 3 && arr[0].as_str() == Some("EVENT") {
                    if let Ok(event) = serde_json::from_value::<NostrEvent>(arr[2].clone()) {
                        return Ok(Some(event));
                    }
                } else if arr.len() >= 2 && arr[0].as_str() == Some("EOSE") {
                    debug!("End of stored events");
                } else if arr.len() >= 2 && arr[0].as_str() == Some("OK") {
                    debug!("Event accepted: {:?}", arr);
                } else if arr.len() >= 2 && arr[0].as_str() == Some("NOTICE") {
                    warn!("Relay notice: {:?}", arr);
                }
            }
        }

        Ok(None)
    }

    /// Compute ECDH shared secret with a public key
    fn compute_shared_secret(&self, their_pubkey: &PublicKey) -> [u8; 32] {
        let shared = SharedSecret::new(their_pubkey, &self.secret_key);
        let mut key = [0u8; 32];
        key.copy_from_slice(shared.as_ref());
        key
    }
}

/// Parse a hex pubkey (x-only or full) into a PublicKey
fn parse_pubkey(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str)?;

    if bytes.len() == 32 {
        // X-only public key, add 0x02 prefix for even Y
        let mut full = vec![0x02];
        full.extend_from_slice(&bytes);
        Ok(PublicKey::from_slice(&full)?)
    } else if bytes.len() == 33 {
        Ok(PublicKey::from_slice(&bytes)?)
    } else {
        Err(anyhow!("Invalid public key length: {}", bytes.len()))
    }
}

/// Encrypt plaintext using NIP-04 (AES-256-CBC with PKCS7 padding)
///
/// Format: base64(ciphertext)?iv=base64(iv)
/// This matches the web app's nostr.js implementation.
fn encrypt_nip04(plaintext: &str, shared_secret: &[u8; 32]) -> Result<String> {
    use rand::RngCore;

    // Generate random 16-byte IV for AES-CBC
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Encrypt with AES-256-CBC + PKCS7 padding
    let cipher = Aes256CbcEnc::new_from_slices(shared_secret, &iv)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

    let plaintext_bytes = plaintext.as_bytes();
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext_bytes);

    // Format: base64(ciphertext)?iv=base64(iv)
    Ok(format!(
        "{}?iv={}",
        BASE64.encode(&ciphertext),
        BASE64.encode(&iv)
    ))
}

/// Decrypt NIP-04 ciphertext (AES-256-CBC with PKCS7 padding)
fn decrypt_nip04(encrypted: &str, shared_secret: &[u8; 32]) -> Result<String> {
    // Parse format: base64(ciphertext)?iv=base64(iv)
    let parts: Vec<&str> = encrypted.split("?iv=").collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid NIP-04 format"));
    }

    let ciphertext = BASE64.decode(parts[0])?;
    let iv = BASE64.decode(parts[1])?;

    if iv.len() != 16 {
        return Err(anyhow!("Invalid IV length: {} (expected 16)", iv.len()));
    }

    // Decrypt with AES-256-CBC + PKCS7 padding
    let cipher = Aes256CbcDec::new_from_slices(shared_secret, &iv)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

    let plaintext = cipher
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_nip04() {
        let shared_secret = [0x42u8; 32];
        let plaintext = "Hello, Drista!";

        let encrypted = encrypt_nip04(plaintext, &shared_secret).unwrap();

        // Verify format
        assert!(encrypted.contains("?iv="), "Should have IV separator");

        let decrypted = decrypt_nip04(&encrypted, &shared_secret).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let shared_secret = [0x42u8; 32];
        let plaintext = "Hello 你好 مرحبا 🎉";

        let encrypted = encrypt_nip04(plaintext, &shared_secret).unwrap();
        let decrypted = decrypt_nip04(&encrypted, &shared_secret).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_event_id() {
        let mut event = NostrEvent {
            id: String::new(),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 1,
            tags: vec![],
            content: "Hello".to_string(),
            sig: String::new(),
        };

        event.compute_id();
        assert_eq!(event.id.len(), 64);
    }

    #[test]
    fn test_iv_is_16_bytes() {
        let shared_secret = [0x42u8; 32];
        let plaintext = "test";

        let encrypted = encrypt_nip04(plaintext, &shared_secret).unwrap();
        let parts: Vec<&str> = encrypted.split("?iv=").collect();
        let iv = BASE64.decode(parts[1]).unwrap();

        assert_eq!(iv.len(), 16, "IV should be 16 bytes for AES-CBC");
    }
}
