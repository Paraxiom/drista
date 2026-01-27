//! Quantum Communicator Desktop App (Tauri)

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use qcomm_core::{Identity, Config, QuantumCommunicator};
use tauri::State;
use std::sync::Mutex;

/// App state
struct AppState {
    communicator: Mutex<Option<QuantumCommunicator>>,
}

/// Initialize the communicator
#[tauri::command]
fn init_communicator(state: State<AppState>) -> Result<String, String> {
    let config = Config::default();
    let communicator = QuantumCommunicator::new(config)
        .map_err(|e| e.to_string())?;

    let fingerprint = communicator.identity().fingerprint().to_hex();

    *state.communicator.lock().unwrap() = Some(communicator);

    Ok(fingerprint)
}

/// Get the current fingerprint
#[tauri::command]
fn get_fingerprint(state: State<AppState>) -> Result<String, String> {
    let guard = state.communicator.lock().unwrap();
    let communicator = guard.as_ref().ok_or("Not initialized")?;

    Ok(communicator.identity().fingerprint().to_hex())
}

/// Check if QRNG is available
#[tauri::command]
fn is_qrng_available() -> bool {
    qcomm_core::crypto::qrng::is_hardware_available()
}

/// Get version
#[tauri::command]
fn get_version() -> String {
    qcomm_core::VERSION.to_string()
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            communicator: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            init_communicator,
            get_fingerprint,
            is_qrng_available,
            get_version,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
