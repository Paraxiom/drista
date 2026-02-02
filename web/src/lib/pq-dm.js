/**
 * Post-Quantum Direct Messages for Drista
 *
 * Implements PQC-encrypted DMs using ML-KEM-1024 (FIPS 203) + AES-256-GCM.
 * Replaces classical NIP-04 encryption with post-quantum security.
 *
 * Key Distribution:
 * - Users publish ML-KEM-1024 encapsulation keys as Nostr events (kind 30078)
 * - When starting a DM, fetch recipient's EK via Nostr REQ
 * - Cache discovered keys in localStorage
 *
 * Encryption Flow:
 * 1. Fetch recipient's encapsulation key (1568 bytes)
 * 2. Encapsulate(EK) -> ciphertext (1568 bytes) + shared_secret (32 bytes)
 * 3. HKDF(shared_secret) -> AES key (32 bytes)
 * 4. AES-256-GCM(message) -> encrypted content
 * 5. Send kind 20004 event with KEM_CT + nonce + AES_CT
 */

import { initWasm, getWasm, isWasmReady } from './wasm.js';

// Storage keys
const IDENTITY_KEY = 'pq_dm_identity';
const PEER_KEYS_PREFIX = 'pq_peer_';

// In-memory caches
let mlKemKeypair = null;
let pqDmInitialized = false;

// Cached peer encapsulation keys (pubkey -> base64 EK)
const peerEkCache = new Map();

/**
 * Initialize PQ-DM identity
 * Generates or loads ML-KEM-768 keypair for this identity
 * @returns {Promise<string>} Our encapsulation key (base64, 1184 bytes)
 */
export async function initPqDm() {
  if (pqDmInitialized && mlKemKeypair) {
    return mlKemKeypair.publicKeyBase64;
  }

  await initWasm();
  const wasm = getWasm();

  // Generate fresh ML-KEM-768 keypair
  // Note: We regenerate each session for forward secrecy
  // The secret key cannot be safely stored in localStorage
  mlKemKeypair = new wasm.JsMlKemKeyPair();
  pqDmInitialized = true;

  // Store our public key for reference
  localStorage.setItem(IDENTITY_KEY, JSON.stringify({
    encapsulationKey: mlKemKeypair.publicKeyBase64,
    timestamp: Date.now()
  }));

  // Load cached peer keys from localStorage
  loadCachedPeerKeys();

  console.log('[PQ-DM] Identity initialized, EK:', mlKemKeypair.publicKeyBase64.slice(0, 32) + '...');

  return mlKemKeypair.publicKeyBase64;
}

/**
 * Get our encapsulation key for sharing
 * @returns {string|null} Base64 encapsulation key
 */
export function getEncapsulationKey() {
  return mlKemKeypair?.publicKeyBase64 || null;
}

/**
 * Check if PQ-DM is initialized
 */
export function isPqDmReady() {
  return pqDmInitialized && mlKemKeypair !== null;
}

/**
 * Load cached peer keys from localStorage
 */
function loadCachedPeerKeys() {
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(PEER_KEYS_PREFIX)) {
        const pubkey = key.slice(PEER_KEYS_PREFIX.length);
        const data = JSON.parse(localStorage.getItem(key));
        if (data && data.ek) {
          peerEkCache.set(pubkey, data.ek);
        }
      }
    }
    if (peerEkCache.size > 0) {
      console.log(`[PQ-DM] Loaded ${peerEkCache.size} cached peer keys`);
    }
  } catch (e) {
    console.warn('[PQ-DM] Failed to load cached peer keys:', e);
  }
}

/**
 * Cache a peer's encapsulation key
 * @param {string} pubkey - Nostr public key (hex)
 * @param {string} ekBase64 - Encapsulation key (base64)
 */
function cachePeerKey(pubkey, ekBase64) {
  peerEkCache.set(pubkey, ekBase64);
  localStorage.setItem(PEER_KEYS_PREFIX + pubkey, JSON.stringify({
    ek: ekBase64,
    timestamp: Date.now()
  }));
}

/**
 * Check if a peer has a PQ key (in cache)
 * @param {string} pubkey - Nostr public key (hex)
 * @returns {boolean}
 */
export function hasPqKey(pubkey) {
  return peerEkCache.has(pubkey);
}

/**
 * Get a peer's encapsulation key from cache
 * @param {string} pubkey - Nostr public key (hex)
 * @returns {string|null} Base64 encapsulation key or null
 */
export function getPeerKey(pubkey) {
  return peerEkCache.get(pubkey) || null;
}

/**
 * Register a discovered peer key (from kind 30078 event or message tag)
 * @param {string} pubkey - Nostr public key (hex)
 * @param {string} ekBase64 - Encapsulation key (base64)
 */
export function registerPeerKey(pubkey, ekBase64) {
  if (!ekBase64 || ekBase64.length < 100) {
    console.warn('[PQ-DM] Invalid peer EK, ignoring');
    return;
  }
  cachePeerKey(pubkey, ekBase64);
  console.log(`[PQ-DM] Registered peer key: ${pubkey.slice(0, 16)}...`);
}

/**
 * Publish our PQ encapsulation key as a Nostr event (kind 30078)
 * This is a replaceable event (NIP-33 parameterized replaceable)
 *
 * @param {Object} nostrClient - NostrClient instance
 * @returns {Promise<Object>} The published event
 */
export async function publishPqKey(nostrClient) {
  if (!isPqDmReady()) {
    throw new Error('PQ-DM not initialized');
  }

  // Import createEvent from nostr.js
  const { createEvent, KIND } = await import('./nostr.js');

  const event = createEvent(
    KIND.PQ_KEY,
    '', // Empty content
    [
      ['d', 'ml-kem-1024'], // NIP-33 identifier
      ['ek', mlKemKeypair.publicKeyBase64] // Our encapsulation key
    ],
    nostrClient.privateKey
  );

  // Publish to all connected relays
  for (const relay of nostrClient.relays.values()) {
    if (relay.connected) {
      relay.publish(event);
    }
  }

  console.log('[PQ-DM] Published encapsulation key, event:', event.id.slice(0, 16) + '...');
  return event;
}

/**
 * Fetch a peer's PQ key from relays
 *
 * @param {Object} nostrClient - NostrClient instance
 * @param {string} pubkey - Peer's Nostr public key (hex)
 * @returns {Promise<string|null>} Base64 encapsulation key or null
 */
export async function fetchPqKey(nostrClient, pubkey) {
  // Check cache first
  if (peerEkCache.has(pubkey)) {
    return peerEkCache.get(pubkey);
  }

  const { KIND } = await import('./nostr.js');

  return new Promise((resolve) => {
    let resolved = false;
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        resolve(null);
      }
    }, 5000); // 5 second timeout

    const filter = {
      kinds: [KIND.PQ_KEY],
      authors: [pubkey],
      '#d': ['ml-kem-768'],
      limit: 1
    };

    // Subscribe on all connected relays
    for (const relay of nostrClient.relays.values()) {
      if (!relay.connected) continue;

      const subId = relay.subscribe([filter], (event) => {
        if (resolved) return;

        const ekTag = event.tags.find(t => t[0] === 'ek');
        if (ekTag && ekTag[1]) {
          clearTimeout(timeout);
          resolved = true;
          registerPeerKey(pubkey, ekTag[1]);
          relay.unsubscribe(subId);
          resolve(ekTag[1]);
        }
      });

      // Unsubscribe after timeout
      setTimeout(() => {
        try {
          relay.unsubscribe(subId);
        } catch { /* ignore */ }
      }, 5100);
    }
  });
}

/**
 * Encrypt a message for PQ DM using ML-KEM-1024 + AES-256-GCM
 *
 * Format: base64(kem_ciphertext_1568 || nonce_12 || aes_ciphertext)
 *
 * @param {string} recipientPubkey - Recipient's Nostr public key (hex)
 * @param {string} plaintext - Message to encrypt
 * @returns {Promise<Object>} { content: base64 encrypted, senderEk: our EK }
 */
export async function encryptPqDm(recipientPubkey, plaintext) {
  if (!isPqDmReady()) {
    throw new Error('PQ-DM not initialized');
  }

  const recipientEk = peerEkCache.get(recipientPubkey);
  if (!recipientEk) {
    throw new Error(`No PQ key for recipient: ${recipientPubkey.slice(0, 16)}...`);
  }

  const wasm = getWasm();

  // ML-KEM-1024 encapsulation: generate shared secret + ciphertext
  // pqKeyExchangeInitiate returns a Map
  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientEk);
  const kemCiphertext = base64ToBytes(exchangeMap.get('ciphertext')); // 1568 bytes
  const sharedSecret = base64ToBytes(exchangeMap.get('sharedSecret')); // 32 bytes

  // Derive AES key using HKDF-SHA256
  const aesKey = await deriveAesKey(sharedSecret, 'pq-dm-v1');

  // Generate nonce (12 bytes for AES-GCM)
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // AES-256-GCM encrypt
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    aesKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const aesCiphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    cryptoKey,
    plaintextBytes
  );

  // Combine: KEM_CT (1088) || nonce (12) || AES_CT (variable)
  const combined = new Uint8Array(kemCiphertext.length + nonce.length + aesCiphertext.byteLength);
  combined.set(kemCiphertext, 0);
  combined.set(nonce, kemCiphertext.length);
  combined.set(new Uint8Array(aesCiphertext), kemCiphertext.length + nonce.length);

  const content = bytesToBase64(combined);

  console.log('[PQ-DM] Encrypting with ML-KEM-1024, payload:', combined.length, 'bytes');

  return {
    content,
    senderEk: mlKemKeypair.publicKeyBase64
  };
}

/**
 * Decrypt a PQ DM message
 *
 * @param {string} senderPubkey - Sender's Nostr public key (hex)
 * @param {string} content - Base64 encrypted content
 * @returns {Promise<string>} Decrypted plaintext
 */
export async function decryptPqDm(senderPubkey, content) {
  if (!isPqDmReady()) {
    throw new Error('PQ-DM not initialized');
  }

  const combined = base64ToBytes(content);

  // Parse: KEM_CT (1568) || nonce (12) || AES_CT (rest)
  const kemCiphertext = combined.slice(0, 1568);
  const nonce = combined.slice(1568, 1568 + 12);
  const aesCiphertext = combined.slice(1568 + 12);

  // Decapsulate to get shared secret
  const kemCtBase64 = bytesToBase64(kemCiphertext);
  const sharedSecretBase64 = mlKemKeypair.decapsulate(kemCtBase64);
  const sharedSecret = base64ToBytes(sharedSecretBase64);

  // Derive AES key using HKDF-SHA256
  const aesKey = await deriveAesKey(sharedSecret, 'pq-dm-v1');

  // AES-256-GCM decrypt
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    aesKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plaintextBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    cryptoKey,
    aesCiphertext
  );

  const plaintext = new TextDecoder().decode(plaintextBytes);

  console.log('[PQ-DM] Decrypted message from:', senderPubkey.slice(0, 16) + '...');

  return plaintext;
}

/**
 * Derive AES-256 key from shared secret using HKDF-SHA256
 */
async function deriveAesKey(sharedSecret, info) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32), // Zero salt (shared secret already has sufficient entropy)
      info: new TextEncoder().encode(info)
    },
    keyMaterial,
    256 // 32 bytes
  );

  return new Uint8Array(derivedBits);
}

/**
 * Handle incoming kind 30078 (PQ key publication) event
 * @param {Object} event - Nostr event
 */
export function handlePqKeyEvent(event) {
  if (event.kind !== 30078) return;

  const ekTag = event.tags.find(t => t[0] === 'ek');
  const dTag = event.tags.find(t => t[0] === 'd');

  if (dTag && dTag[1] === 'ml-kem-768' && ekTag && ekTag[1]) {
    registerPeerKey(event.pubkey, ekTag[1]);
  }
}

// ── Utility functions ───────────────────────────────────────

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export default {
  initPqDm,
  getEncapsulationKey,
  isPqDmReady,
  hasPqKey,
  getPeerKey,
  registerPeerKey,
  publishPqKey,
  fetchPqKey,
  encryptPqDm,
  decryptPqDm,
  handlePqKeyEvent
};
