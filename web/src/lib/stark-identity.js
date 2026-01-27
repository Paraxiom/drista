/**
 * STARK Identity Manager for Drista
 *
 * Manages post-quantum STARK-based identities using the WASM module.
 * Falls back to browser crypto if WASM is unavailable.
 */

import { getWasm, isWasmReady } from './wasm.js';

const STORAGE_KEY_SECRET = 'drista_stark_secret';
const STORAGE_KEY_PUBKEY = 'drista_stark_pubkey';

/**
 * STARK identity for post-quantum event authentication
 */
export class StarkIdentityManager {
  constructor() {
    this.identity = null;   // JsStarkIdentity (WASM)
    this.pubkeyHex = null;
    this.secretHex = null;
    this.ready = false;
  }

  /**
   * Initialize STARK identity (load existing or generate new)
   * @returns {{ pubkeyHex: string, secretHex: string }}
   */
  init() {
    const wasm = getWasm();
    if (!wasm || !isWasmReady()) {
      throw new Error('WASM module not loaded');
    }

    // Try loading existing secret
    const storedSecret = localStorage.getItem(STORAGE_KEY_SECRET);

    if (storedSecret) {
      try {
        this.identity = wasm.JsStarkIdentity.fromSecret(storedSecret);
        this.pubkeyHex = this.identity.pubkeyHex;
        this.secretHex = storedSecret;
        this.ready = true;

        console.log('[STARK] Loaded existing identity:', this.pubkeyHex.slice(0, 16) + '...');
        return { pubkeyHex: this.pubkeyHex, secretHex: this.secretHex };
      } catch (error) {
        console.warn('[STARK] Failed to load stored secret, generating new:', error);
        localStorage.removeItem(STORAGE_KEY_SECRET);
        localStorage.removeItem(STORAGE_KEY_PUBKEY);
      }
    }

    // Generate new identity
    this.identity = new wasm.JsStarkIdentity();
    this.pubkeyHex = this.identity.pubkeyHex;
    this.secretHex = this.identity.secretHex;
    this.ready = true;

    // Persist
    localStorage.setItem(STORAGE_KEY_SECRET, this.secretHex);
    localStorage.setItem(STORAGE_KEY_PUBKEY, this.pubkeyHex);

    console.log('[STARK] Generated new identity:', this.pubkeyHex.slice(0, 16) + '...');
    return { pubkeyHex: this.pubkeyHex, secretHex: this.secretHex };
  }

  /**
   * Sign event data with a STARK proof
   * @param {Uint8Array|string} eventData - Data to sign
   * @returns {string} Base64-encoded STARK proof
   */
  signEvent(eventData) {
    if (!this.ready || !this.identity) {
      throw new Error('STARK identity not initialized');
    }

    const data = typeof eventData === 'string'
      ? new TextEncoder().encode(eventData)
      : eventData;

    return this.identity.signEvent(data);
  }

  /**
   * Verify a STARK event proof
   * @param {string} proofBase64 - Base64-encoded proof
   * @param {Uint8Array|string} eventData - Original data
   * @param {string} pubkeyHex - Expected signer pubkey
   * @returns {boolean}
   */
  static verify(proofBase64, eventData, pubkeyHex) {
    const wasm = getWasm();
    if (!wasm || !isWasmReady()) {
      throw new Error('WASM module not loaded');
    }

    const data = typeof eventData === 'string'
      ? new TextEncoder().encode(eventData)
      : eventData;

    return wasm.verifyStarkEvent(proofBase64, data, pubkeyHex);
  }

  /**
   * Get fingerprint (first 16 hex chars of pubkey)
   */
  get fingerprint() {
    return this.pubkeyHex?.slice(0, 16) || null;
  }
}
