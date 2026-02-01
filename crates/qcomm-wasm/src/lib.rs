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

// ============================================================================
// PQ Triple Ratchet - Post-Quantum Forward-Secure Messaging
// ============================================================================

use qcomm_core::crypto::{MlKemKeyPair, MlKemPublicKey, SharedSecret, PqTripleRatchet, RatchetHeader};

/// ML-KEM-1024 keypair for initial key exchange
#[wasm_bindgen]
pub struct JsMlKemKeyPair {
    inner: MlKemKeyPair,
}

#[wasm_bindgen]
impl JsMlKemKeyPair {
    /// Generate a new ML-KEM keypair
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<JsMlKemKeyPair, JsError> {
        let inner = MlKemKeyPair::generate()
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self { inner })
    }

    /// Get public key as base64
    #[wasm_bindgen(getter, js_name = publicKeyBase64)]
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.inner.public_key().as_bytes())
    }

    /// Encapsulate a shared secret to this public key
    /// Returns { ciphertext: base64, sharedSecret: base64 }
    #[wasm_bindgen(js_name = encapsulate)]
    pub fn encapsulate(&self) -> Result<JsValue, JsError> {
        let (ct, ss) = self.inner.public_key().encapsulate()
            .map_err(|e| JsError::new(&e.to_string()))?;

        let result = serde_json::json!({
            "ciphertext": BASE64.encode(ct.as_bytes()),
            "sharedSecret": BASE64.encode(ss.as_bytes())
        });

        serde_wasm_bindgen::to_value(&result)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Decapsulate shared secret from ciphertext
    #[wasm_bindgen(js_name = decapsulate)]
    pub fn decapsulate(&self, ciphertext_base64: &str) -> Result<String, JsError> {
        let ct_bytes = BASE64.decode(ciphertext_base64)
            .map_err(|e| JsError::new(&format!("Invalid base64: {}", e)))?;

        let ct = qcomm_core::crypto::MlKemCiphertext::from_bytes(&ct_bytes)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let ss = self.inner.decapsulate(&ct)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(BASE64.encode(ss.as_bytes()))
    }
}

/// PQ Triple Ratchet session for forward-secure messaging
#[wasm_bindgen]
pub struct JsPqSession {
    inner: PqTripleRatchet,
}

#[wasm_bindgen]
impl JsPqSession {
    /// Initialize as session initiator (Alice)
    /// shared_secret_base64: The shared secret from initial key exchange
    /// their_public_key_base64: Bob's ML-KEM public key
    #[wasm_bindgen(js_name = initAsInitiator)]
    pub fn init_as_initiator(
        shared_secret_base64: &str,
        their_public_key_base64: &str,
    ) -> Result<JsPqSession, JsError> {
        let ss_bytes = BASE64.decode(shared_secret_base64)
            .map_err(|e| JsError::new(&format!("Invalid shared secret base64: {}", e)))?;
        let pk_bytes = BASE64.decode(their_public_key_base64)
            .map_err(|e| JsError::new(&format!("Invalid public key base64: {}", e)))?;

        let shared_secret = SharedSecret::from_bytes(&ss_bytes)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let their_pk = MlKemPublicKey::from_bytes(&pk_bytes)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let inner = PqTripleRatchet::init_initiator(shared_secret, their_pk)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(Self { inner })
    }

    /// Initialize as session responder (Bob)
    /// shared_secret_base64: The shared secret from initial key exchange
    /// keypair: Our ML-KEM keypair used in the initial exchange
    #[wasm_bindgen(js_name = initAsResponder)]
    pub fn init_as_responder(
        shared_secret_base64: &str,
        keypair: JsMlKemKeyPair,
    ) -> Result<JsPqSession, JsError> {
        let ss_bytes = BASE64.decode(shared_secret_base64)
            .map_err(|e| JsError::new(&format!("Invalid shared secret base64: {}", e)))?;

        let shared_secret = SharedSecret::from_bytes(&ss_bytes)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let inner = PqTripleRatchet::init_responder(shared_secret, keypair.inner)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(Self { inner })
    }

    /// Get our current public key (for sending in headers)
    #[wasm_bindgen(getter, js_name = ourPublicKeyBase64)]
    pub fn our_public_key_base64(&self) -> String {
        BASE64.encode(&self.inner.our_public_key_bytes())
    }

    /// Encrypt a message
    /// Returns { header: base64, ciphertext: base64 }
    #[wasm_bindgen]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<JsValue, JsError> {
        let (header, ciphertext) = self.inner.encrypt(plaintext)
            .map_err(|e| JsError::new(&e.to_string()))?;

        // Serialize header to JSON then base64
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let result = serde_json::json!({
            "header": BASE64.encode(&header_json),
            "ciphertext": BASE64.encode(&ciphertext)
        });

        serde_wasm_bindgen::to_value(&result)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Decrypt a message
    #[wasm_bindgen]
    pub fn decrypt(&mut self, header_base64: &str, ciphertext_base64: &str) -> Result<Vec<u8>, JsError> {
        let header_json = BASE64.decode(header_base64)
            .map_err(|e| JsError::new(&format!("Invalid header base64: {}", e)))?;
        let ciphertext = BASE64.decode(ciphertext_base64)
            .map_err(|e| JsError::new(&format!("Invalid ciphertext base64: {}", e)))?;

        let header: RatchetHeader = serde_json::from_slice(&header_json)
            .map_err(|e| JsError::new(&format!("Invalid header JSON: {}", e)))?;

        self.inner.decrypt(&header, &ciphertext)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Helper: Perform initial key exchange (Alice side)
/// Returns { ciphertext, sharedSecret, theirPublicKey } all as base64
#[wasm_bindgen(js_name = pqKeyExchangeInitiate)]
pub fn pq_key_exchange_initiate(their_public_key_base64: &str) -> Result<JsValue, JsError> {
    let pk_bytes = BASE64.decode(their_public_key_base64)
        .map_err(|e| JsError::new(&format!("Invalid public key base64: {}", e)))?;

    let their_pk = MlKemPublicKey::from_bytes(&pk_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let (ct, ss) = their_pk.encapsulate()
        .map_err(|e| JsError::new(&e.to_string()))?;

    let result = serde_json::json!({
        "ciphertext": BASE64.encode(ct.as_bytes()),
        "sharedSecret": BASE64.encode(ss.as_bytes()),
        "theirPublicKey": their_public_key_base64
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&e.to_string()))
}
