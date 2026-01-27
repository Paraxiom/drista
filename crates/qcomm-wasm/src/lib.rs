//! WebAssembly bindings for Quantum Communicator
//!
//! Exposes STARK proofs, QRNG, and AEAD encryption to JavaScript.
//! Native-crypto features (SPHINCS+, ML-KEM, Noise) require the native build.

use wasm_bindgen::prelude::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use qcomm_core::crypto::qrng;
use qcomm_core::crypto::stark::{StarkIdentity, EventProof, prove_event, verify_event};

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ============================================================================
// STARK Proofs - Post-Quantum Event Authentication
// ============================================================================

/// JavaScript wrapper for STARK-based identity
#[wasm_bindgen]
pub struct JsStarkIdentity {
    inner: StarkIdentity,
    secret: [u8; 32],
}

#[wasm_bindgen]
impl JsStarkIdentity {
    /// Generate a new STARK identity from random secret
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<JsStarkIdentity, JsError> {
        let entropy = qcomm_core::crypto::qrng::get_entropy(32)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&entropy);

        let inner = StarkIdentity::from_secret(&secret);

        Ok(Self { inner, secret })
    }

    /// Create identity from existing secret (32 bytes, hex encoded)
    #[wasm_bindgen(js_name = fromSecret)]
    pub fn from_secret(secret_hex: &str) -> Result<JsStarkIdentity, JsError> {
        let secret_bytes = hex::decode(secret_hex)
            .map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;

        if secret_bytes.len() != 32 {
            return Err(JsError::new("Secret must be 32 bytes"));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);

        let inner = StarkIdentity::from_secret(&secret);

        Ok(Self { inner, secret })
    }

    /// Get public key hash as hex string
    #[wasm_bindgen(getter, js_name = pubkeyHex)]
    pub fn pubkey_hex(&self) -> String {
        self.inner.to_hex()
    }

    /// Get secret key as hex string
    #[wasm_bindgen(getter, js_name = secretHex)]
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret)
    }

    /// Sign event data with STARK proof
    /// Returns the proof as base64-encoded bytes
    #[wasm_bindgen(js_name = signEvent)]
    pub fn sign_event(&self, event_data: &[u8]) -> Result<String, JsError> {
        let proof = prove_event(&self.secret, event_data)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let bytes = proof.serialize();
        Ok(BASE64.encode(&bytes))
    }
}

/// Verify a STARK event proof
#[wasm_bindgen(js_name = verifyStarkEvent)]
pub fn verify_stark_event(
    proof_base64: &str,
    event_data: &[u8],
    pubkey_hex: &str,
) -> Result<bool, JsError> {
    let proof_bytes = BASE64.decode(proof_base64)
        .map_err(|e| JsError::new(&format!("Invalid base64: {}", e)))?;

    let proof = EventProof::deserialize(&proof_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;

    if pubkey_bytes.len() != 32 {
        return Err(JsError::new("Pubkey must be 32 bytes"));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pubkey_bytes);

    verify_event(&proof, event_data, &pubkey)
        .map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// QRNG / AEAD
// ============================================================================

/// Get random bytes from QRNG (falls back to CSPRNG if unavailable)
#[wasm_bindgen]
pub fn get_random_bytes(count: usize) -> Result<Vec<u8>, JsError> {
    qrng::get_entropy(count)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Check if hardware QRNG is available
#[wasm_bindgen]
pub fn is_qrng_available() -> bool {
    qrng::is_hardware_available()
}

/// Encrypt a message (AES-256-GCM)
#[wasm_bindgen]
pub fn encrypt_message(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, JsError> {
    use qcomm_core::crypto::aead;
    aead::encrypt(plaintext, key, &[])
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypt a message (AES-256-GCM)
#[wasm_bindgen]
pub fn decrypt_message(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, JsError> {
    use qcomm_core::crypto::aead;
    aead::decrypt(ciphertext, key, &[])
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Get library version
#[wasm_bindgen]
pub fn version() -> String {
    qcomm_core::VERSION.to_string()
}
