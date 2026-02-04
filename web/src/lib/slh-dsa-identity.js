/**
 * SLH-DSA (SPHINCS+) Post-Quantum Identity Manager
 *
 * Uses FIPS 205 SLH-DSA-SHAKE-128s for post-quantum signatures.
 * This provides NIST Level 1 security (128-bit classical / 64-bit quantum).
 *
 * Signature size: ~7.8 KB
 * Public key: 32 bytes
 */

import { getWasm, isWasmReady } from './wasm.js';

const STORAGE_KEY_SK = 'drista_slh_dsa_secret';
const STORAGE_KEY_PK = 'drista_slh_dsa_pubkey';

let slhDsaKeyPair = null;
let slhDsaPublicKey = null;

/**
 * Initialize or restore SLH-DSA identity
 * @returns {Object} { publicKeyBase64, isNew }
 */
export function initSlhDsaIdentity() {
  if (!isWasmReady()) {
    throw new Error('WASM not ready');
  }

  const wasm = getWasm();

  // Try to restore from localStorage
  const storedSk = localStorage.getItem(STORAGE_KEY_SK);
  const storedPk = localStorage.getItem(STORAGE_KEY_PK);

  if (storedSk && storedPk) {
    try {
      slhDsaKeyPair = wasm.JsSlhDsaKeyPair.fromKeys(storedSk, storedPk);
      slhDsaPublicKey = storedPk;
      console.log('[SLH-DSA] Restored existing identity');
      return { publicKeyBase64: slhDsaPublicKey, isNew: false };
    } catch (error) {
      console.warn('[SLH-DSA] Failed to restore identity, generating new:', error);
    }
  }

  // Generate new keypair
  slhDsaKeyPair = new wasm.JsSlhDsaKeyPair();
  slhDsaPublicKey = slhDsaKeyPair.publicKeyBase64;

  // Store keys
  localStorage.setItem(STORAGE_KEY_SK, slhDsaKeyPair.privateKeyBase64);
  localStorage.setItem(STORAGE_KEY_PK, slhDsaPublicKey);

  console.log('[SLH-DSA] Generated new identity');
  return { publicKeyBase64: slhDsaPublicKey, isNew: true };
}

/**
 * Check if SLH-DSA identity is initialized
 */
export function isSlhDsaReady() {
  return slhDsaKeyPair !== null;
}

/**
 * Get the SLH-DSA public key (base64)
 */
export function getSlhDsaPublicKey() {
  return slhDsaPublicKey;
}

/**
 * Get the first 16 chars of the public key as fingerprint
 */
export function getSlhDsaFingerprint() {
  if (!slhDsaPublicKey) return null;
  return slhDsaPublicKey.slice(0, 16);
}

/**
 * Sign data with SLH-DSA
 * @param {Uint8Array|string} data - Data to sign
 * @returns {string} Base64-encoded signature (~10.5 KB encoded)
 */
export function signWithSlhDsa(data) {
  if (!slhDsaKeyPair) {
    throw new Error('SLH-DSA not initialized');
  }

  if (typeof data === 'string') {
    return slhDsaKeyPair.signString(data);
  }

  return slhDsaKeyPair.sign(data);
}

/**
 * Verify a SLH-DSA signature
 * @param {string} publicKeyBase64 - Signer's public key
 * @param {Uint8Array|string} data - Original data
 * @param {string} signatureBase64 - Signature to verify
 * @returns {boolean}
 */
export function verifySlhDsaSignature(publicKeyBase64, data, signatureBase64) {
  if (!isWasmReady()) {
    throw new Error('WASM not ready');
  }

  const wasm = getWasm();

  let dataBytes;
  if (typeof data === 'string') {
    dataBytes = new TextEncoder().encode(data);
  } else {
    dataBytes = data;
  }

  return wasm.verifySlhDsaSignature(publicKeyBase64, dataBytes, signatureBase64);
}

/**
 * Get signature size in bytes (for UI display)
 */
export function getSignatureSize() {
  if (!isWasmReady()) return 7856; // Default for SLH-DSA-SHAKE-128s
  const wasm = getWasm();
  return wasm.getSlhDsaSignatureSize();
}

/**
 * Get public key size in bytes
 */
export function getPublicKeySize() {
  if (!isWasmReady()) return 32;
  const wasm = getWasm();
  return wasm.getSlhDsaPublicKeySize();
}

/**
 * Clear stored identity (for testing/reset)
 */
export function clearSlhDsaIdentity() {
  localStorage.removeItem(STORAGE_KEY_SK);
  localStorage.removeItem(STORAGE_KEY_PK);
  slhDsaKeyPair = null;
  slhDsaPublicKey = null;
}
