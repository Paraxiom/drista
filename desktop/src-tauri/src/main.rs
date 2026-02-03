//! Quantum Communicator Desktop App (Tauri)
//!
//! Features:
//! - Post-quantum encryption (ML-KEM-1024)
//! - BLE mesh networking (BitChat compatible)
//! - STARK identity proofs
//! - Nostr transport fallback

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use qcomm_core::transport::ble::{BleTransport, BlePeer};
use qcomm_core::transport::Transport;
use qcomm_core::crypto::qrng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;

/// BLE peer info for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub name: Option<String>,
    pub rssi: i16,
    pub supports_pqc: bool,
    pub last_seen: u64,
}

impl From<BlePeer> for PeerInfo {
    fn from(peer: BlePeer) -> Self {
        Self {
            address: peer.address,
            name: peer.name,
            rssi: peer.rssi,
            supports_pqc: peer.supports_pqc,
            last_seen: peer.last_seen,
        }
    }
}

/// App state with BLE transport
struct AppState {
    ble_transport: Arc<Mutex<Option<BleTransport>>>,
}

/// Initialize the BLE transport
#[tauri::command]
async fn init_ble(state: State<'_, AppState>) -> Result<String, String> {
    let transport = BleTransport::new()
        .map_err(|e| format!("Failed to create BLE transport: {}", e))?;

    // Get our public key before moving transport
    let pk_hex = transport.public_key()
        .map(|pk| hex::encode(pk))
        .unwrap_or_else(|| "no-pk".to_string());

    *state.ble_transport.lock().await = Some(transport);

    Ok(pk_hex)
}

/// Connect BLE transport (start scanning and advertising)
#[tauri::command]
async fn ble_connect(state: State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state.ble_transport.lock().await;
    let transport = guard.as_mut().ok_or("BLE not initialized")?;

    transport.connect().await
        .map_err(|e| format!("BLE connect failed: {}", e))?;

    Ok(true)
}

/// Disconnect BLE transport
#[tauri::command]
async fn ble_disconnect(state: State<'_, AppState>) -> Result<bool, String> {
    let mut guard = state.ble_transport.lock().await;
    let transport = guard.as_mut().ok_or("BLE not initialized")?;

    transport.disconnect().await
        .map_err(|e| format!("BLE disconnect failed: {}", e))?;

    Ok(true)
}

/// Check if BLE is connected
#[tauri::command]
async fn ble_is_connected(state: State<'_, AppState>) -> Result<bool, String> {
    let guard = state.ble_transport.lock().await;
    let transport = guard.as_ref().ok_or("BLE not initialized")?;

    Ok(transport.is_connected().await)
}

/// Get discovered BLE peers
#[tauri::command]
async fn ble_get_peers(state: State<'_, AppState>) -> Result<Vec<PeerInfo>, String> {
    let guard = state.ble_transport.lock().await;
    let transport = guard.as_ref().ok_or("BLE not initialized")?;

    let peers = transport.peers().await;
    Ok(peers.into_iter().map(PeerInfo::from).collect())
}

/// Send encrypted message to peer via BLE
#[tauri::command]
async fn ble_send_message(
    state: State<'_, AppState>,
    peer_address: String,
    message: String,
) -> Result<bool, String> {
    let guard = state.ble_transport.lock().await;
    let transport = guard.as_ref().ok_or("BLE not initialized")?;

    // Encrypt the message
    let encrypted = transport.encrypt_for_peer(&peer_address, message.as_bytes())
        .await
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // In production, would send via BLE characteristic write
    // For now, log that we encrypted successfully
    println!(
        "[BLE] Encrypted message for {}: {} bytes KEM CT, {} bytes ciphertext",
        peer_address,
        encrypted.kem_ct.len(),
        encrypted.ciphertext.len()
    );

    Ok(true)
}

/// Get our BLE public key (ML-KEM encapsulation key)
#[tauri::command]
async fn ble_get_public_key(state: State<'_, AppState>) -> Result<String, String> {
    let guard = state.ble_transport.lock().await;
    let transport = guard.as_ref().ok_or("BLE not initialized")?;

    transport.public_key()
        .map(|pk| hex::encode(pk))
        .ok_or_else(|| "No public key available".to_string())
}

/// Check if QRNG hardware is available
#[tauri::command]
fn is_qrng_available() -> bool {
    qrng::is_hardware_available()
}

/// Get app version
#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get transport capabilities
#[tauri::command]
async fn get_capabilities(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let guard = state.ble_transport.lock().await;
    let transport = guard.as_ref().ok_or("BLE not initialized")?;

    let caps: Vec<String> = transport.capabilities()
        .iter()
        .map(|c| format!("{:?}", c))
        .collect();

    Ok(caps)
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            ble_transport: Arc::new(Mutex::new(None)),
        })
        .invoke_handler(tauri::generate_handler![
            // BLE commands
            init_ble,
            ble_connect,
            ble_disconnect,
            ble_is_connected,
            ble_get_peers,
            ble_send_message,
            ble_get_public_key,
            get_capabilities,
            // System commands
            is_qrng_available,
            get_version,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
