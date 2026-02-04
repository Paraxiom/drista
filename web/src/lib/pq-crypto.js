/**
 * Post-Quantum Cryptography Manager for Drista
 *
 * Manages PQ Triple Ratchet sessions for forward-secure messaging.
 * Uses ML-KEM-1024 for key encapsulation (NIST FIPS 203).
 */

import { initWasm, getWasm, isWasmReady } from './wasm.js';

// Session storage key prefix
const SESSION_PREFIX = 'pq_session_';
const KEYPAIR_KEY = 'pq_identity_keypair';

// In-memory session cache (sessions are stateful)
const activeSessions = new Map();

// Our identity keypair
let identityKeypair = null;

/**
 * Initialize the PQ crypto system
 * Must be called before any other functions
 */
export async function initPqCrypto() {
  await initWasm();

  // Load or generate identity keypair
  const stored = localStorage.getItem(KEYPAIR_KEY);
  if (stored) {
    try {
      const { publicKey } = JSON.parse(stored);
      // We can't restore the full keypair from storage (secret key)
      // so we regenerate on each session start
      console.log('[PQ] Found stored public key, regenerating keypair');
    } catch (e) {
      console.warn('[PQ] Failed to parse stored keypair:', e);
    }
  }

  // Generate fresh identity keypair
  const wasm = getWasm();
  identityKeypair = new wasm.JsMlKemKeyPair();

  // Store our public key for discovery
  localStorage.setItem(KEYPAIR_KEY, JSON.stringify({
    publicKey: identityKeypair.publicKeyBase64
  }));

  console.log('[PQ] Initialized with public key:', identityKeypair.publicKeyBase64.slice(0, 32) + '...');

  return identityKeypair.publicKeyBase64;
}

/**
 * Get our PQ public key (for sharing with peers)
 */
export function getPublicKey() {
  if (!identityKeypair) {
    throw new Error('PQ crypto not initialized. Call initPqCrypto() first.');
  }
  return identityKeypair.publicKeyBase64;
}

/**
 * Initiate a PQ session with a peer (we are Alice)
 * @param {string} peerPubKeyBase64 - Peer's ML-KEM public key
 * @param {string} peerId - Unique identifier for the peer (e.g., Nostr pubkey)
 * @returns {Object} { session, ciphertext } - The session and ciphertext to send to peer
 */
export async function initiateSession(peerPubKeyBase64, peerId) {
  if (!isWasmReady()) {
    await initPqCrypto();
  }

  const wasm = getWasm();

  // Perform key exchange - encapsulate to their public key
  const exchange = wasm.pqKeyExchangeInitiate(peerPubKeyBase64);

  // Create session as initiator
  const session = wasm.JsPqSession.initAsInitiator(
    exchange.sharedSecret,
    peerPubKeyBase64
  );

  // Cache the session
  activeSessions.set(peerId, session);

  console.log('[PQ] Initiated session with peer:', peerId.slice(0, 16) + '...');

  return {
    session,
    ciphertext: exchange.ciphertext, // Send this to peer for them to complete exchange
    ourPublicKey: identityKeypair.publicKeyBase64
  };
}

/**
 * Respond to a PQ session initiation (we are Bob)
 * @param {string} ciphertextBase64 - The encapsulated ciphertext from initiator
 * @param {string} peerId - Unique identifier for the peer
 * @returns {Object} The session
 */
export async function respondToSession(ciphertextBase64, peerId) {
  if (!isWasmReady()) {
    await initPqCrypto();
  }

  const wasm = getWasm();

  // Decapsulate to get shared secret
  const sharedSecretBase64 = identityKeypair.decapsulate(ciphertextBase64);

  // Create session as responder
  // Note: We need a fresh keypair for the ratchet, not our identity keypair
  const ratchetKeypair = new wasm.JsMlKemKeyPair();
  const session = wasm.JsPqSession.initAsResponder(sharedSecretBase64, ratchetKeypair);

  // Cache the session
  activeSessions.set(peerId, session);

  console.log('[PQ] Responded to session from peer:', peerId.slice(0, 16) + '...');

  return { session };
}

/**
 * Get or create a session with a peer
 * @param {string} peerId - Unique identifier for the peer
 * @param {string} peerPubKeyBase64 - Peer's public key (for new sessions)
 */
export async function getOrCreateSession(peerId, peerPubKeyBase64) {
  // Check cache first
  if (activeSessions.has(peerId)) {
    return { session: activeSessions.get(peerId), isNew: false };
  }

  // Create new session as initiator
  const { session, ciphertext, ourPublicKey } = await initiateSession(peerPubKeyBase64, peerId);

  return {
    session,
    isNew: true,
    keyExchange: { ciphertext, ourPublicKey }
  };
}

/**
 * Encrypt a message using the PQ Triple Ratchet
 * @param {string} peerId - Peer identifier
 * @param {Uint8Array|string} message - Message to encrypt
 * @returns {Object} { header, ciphertext } both as base64
 */
export async function encryptMessage(peerId, message) {
  const session = activeSessions.get(peerId);
  if (!session) {
    throw new Error(`No session found for peer: ${peerId}. Call initiateSession or respondToSession first.`);
  }

  // Convert string to bytes if needed
  const messageBytes = typeof message === 'string'
    ? new TextEncoder().encode(message)
    : message;

  const encrypted = session.encrypt(messageBytes);

  return {
    header: encrypted.header,
    ciphertext: encrypted.ciphertext
  };
}

/**
 * Decrypt a message using the PQ Triple Ratchet
 * @param {string} peerId - Peer identifier
 * @param {string} headerBase64 - Message header
 * @param {string} ciphertextBase64 - Encrypted message
 * @returns {Uint8Array} Decrypted plaintext
 */
export async function decryptMessage(peerId, headerBase64, ciphertextBase64) {
  const session = activeSessions.get(peerId);
  if (!session) {
    throw new Error(`No session found for peer: ${peerId}. Call initiateSession or respondToSession first.`);
  }

  const plaintext = session.decrypt(headerBase64, ciphertextBase64);
  return plaintext;
}

/**
 * Check if we have an active session with a peer
 */
export function hasSession(peerId) {
  return activeSessions.has(peerId);
}

/**
 * Clear a session (e.g., on logout or key rotation)
 */
export function clearSession(peerId) {
  const session = activeSessions.get(peerId);
  if (session) {
    // Free WASM memory
    session.free();
    activeSessions.delete(peerId);
    console.log('[PQ] Cleared session for peer:', peerId.slice(0, 16) + '...');
  }
}

/**
 * Clear all sessions
 */
export function clearAllSessions() {
  for (const [peerId, session] of activeSessions) {
    session.free();
  }
  activeSessions.clear();
  console.log('[PQ] Cleared all sessions');
}

/**
 * Create a PQ-encrypted Nostr DM event content
 * Format: "pq1:" + base64(header) + ":" + base64(ciphertext)
 */
export async function createPqDmContent(peerId, message, peerPubKeyBase64) {
  // Ensure we have a session
  let keyExchangeData = null;

  if (!hasSession(peerId)) {
    const result = await getOrCreateSession(peerId, peerPubKeyBase64);
    if (result.isNew) {
      keyExchangeData = result.keyExchange;
    }
  }

  const { header, ciphertext } = await encryptMessage(peerId, message);

  // If this is a new session, include key exchange data
  if (keyExchangeData) {
    // Format: pq1:init:ourPubKey:ciphertext:header:messageCiphertext
    return `pq1:init:${keyExchangeData.ourPublicKey}:${keyExchangeData.ciphertext}:${header}:${ciphertext}`;
  }

  // Format: pq1:msg:header:ciphertext
  return `pq1:msg:${header}:${ciphertext}`;
}

/**
 * Parse and decrypt a PQ-encrypted Nostr DM
 * Supports two formats:
 * - Triple Ratchet: pq1:init:<pubkey>:<kemCT>:<ratchetHeader>:<msgCT>
 * - Simple (CLI): pq1:init:<pubkey>:<kemCT>:<nonce>:<msgCT> (nonce is 16 bytes base64)
 */
export async function parsePqDmContent(peerId, content, senderPubKeyBase64) {
  if (!content.startsWith('pq1:')) {
    throw new Error('Not a PQ-encrypted message');
  }

  const parts = content.split(':');
  const msgType = parts[1];

  if (msgType === 'init') {
    // New session: pq1:init:theirPubKey:keyCiphertext:header_or_nonce:messageCiphertext
    const [, , theirPubKey, keyCiphertext, headerOrNonce, ciphertext] = parts;

    // Detect format: simple format has a short nonce (16 bytes = ~24 chars base64)
    // Triple Ratchet header is much larger (contains KEM ciphertext, etc.)
    const headerBytes = Uint8Array.from(atob(headerOrNonce), c => c.charCodeAt(0));

    if (headerBytes.length <= 16) {
      // Simple format: direct ML-KEM + AES-GCM (from CLI)
      console.log('[PQ] Detected simple PQ-DM format (CLI compatible)');
      return await decryptSimplePqDm(theirPubKey, keyCiphertext, headerOrNonce, ciphertext);
    }

    // Triple Ratchet format
    // Respond to session if we don't have one
    if (!hasSession(peerId)) {
      await respondToSession(keyCiphertext, peerId);
    }

    const plaintext = await decryptMessage(peerId, headerOrNonce, ciphertext);
    return new TextDecoder().decode(plaintext);

  } else if (msgType === 'msg') {
    // Regular message: pq1:msg:header:ciphertext
    const [, , header, ciphertext] = parts;

    if (!hasSession(peerId)) {
      throw new Error('No session established. Need init message first.');
    }

    const plaintext = await decryptMessage(peerId, header, ciphertext);
    return new TextDecoder().decode(plaintext);
  }

  throw new Error(`Unknown PQ message type: ${msgType}`);
}

/**
 * Decrypt a simple PQ-DM (CLI format: ML-KEM + AES-256-GCM, no ratchet)
 * Format: pq1:init:<senderPubKey>:<kemCiphertext>:<nonce>:<ciphertext>
 */
async function decryptSimplePqDm(senderPubKeyBase64, kemCiphertextBase64, nonceBase64, ciphertextBase64) {
  if (!isWasmReady()) {
    await initPqCrypto();
  }

  // Decode components
  const kemCiphertext = Uint8Array.from(atob(kemCiphertextBase64), c => c.charCodeAt(0));
  const nonce = Uint8Array.from(atob(nonceBase64), c => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));

  // Decapsulate shared secret using our identity keypair
  const sharedSecretBase64 = identityKeypair.decapsulate(kemCiphertextBase64);
  const sharedSecret = Uint8Array.from(atob(sharedSecretBase64), c => c.charCodeAt(0));

  // Derive AES key using HKDF (same as CLI: info = "pq-dm-v1")
  const keyMaterial = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decrypt with AES-256-GCM
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    ciphertext
  );

  return new TextDecoder().decode(plaintext);
}

export default {
  initPqCrypto,
  getPublicKey,
  initiateSession,
  respondToSession,
  encryptMessage,
  decryptMessage,
  hasSession,
  clearSession,
  clearAllSessions,
  createPqDmContent,
  parsePqDmContent,
};
