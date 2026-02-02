/**
 * Nostr Client for Drista
 * Implements NIP-01 (basic protocol), NIP-04 (encrypted DMs), and PQ Triple Ratchet
 * Uses real secp256k1 Schnorr signatures via @noble/secp256k1
 * PQ crypto uses ML-KEM-1024 for post-quantum security
 */

import { getSharedSecret } from '@noble/secp256k1';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex as nobleToHex, hexToBytes as nobleFromHex } from '@noble/hashes/utils';
import * as pqCrypto from './pq-crypto.js';

// Nostr event kinds
export const KIND = {
  METADATA: 0,
  TEXT_NOTE: 1,
  RECOMMEND_RELAY: 2,
  CONTACTS: 3,
  ENCRYPTED_DM: 4,        // NIP-04 (legacy secp256k1)
  DELETE: 5,
  REPOST: 6,
  REACTION: 7,
  CHANNEL_CREATE: 40,
  CHANNEL_METADATA: 41,
  CHANNEL_MESSAGE: 42,
  SEALED_DM: 1059,        // NIP-17
  GIFT_WRAP: 1060,        // NIP-17
  PQ_ENCRYPTED_DM: 20004, // Post-Quantum encrypted DM (ML-KEM + Triple Ratchet)
};

// PQ crypto state
let pqInitialized = false;
let pqPublicKey = null;

// Mapping of Nostr pubkeys to PQ public keys (discovered via metadata or handshake)
const pqPeerKeys = new Map();

// Default relays — QuantumHarmony validator bridges (NIP-01 over Mesh Forum)
// ws://localhost:7777 connects via QSSH tunnel (PQ-secured) when tunnel is active.
// wss:// entries are TLS 1.3 fallback for browsers without a QSSH tunnel.
export const DEFAULT_RELAYS = [
  'ws://localhost:7777',             // Local dev or QSSH tunnel endpoint
  'wss://51.79.26.123:7778',        // Alice (Montreal) — TLS fallback
  'wss://51.79.26.168:7778',        // Bob (Beauharnois) — TLS fallback
  'wss://209.38.225.4:7778',        // Charlie (Frankfurt) — TLS fallback
];

/**
 * Initialize PQ cryptography
 * Should be called once at app startup
 */
export async function initPqCrypto() {
  try {
    pqPublicKey = await pqCrypto.initPqCrypto();
    pqInitialized = true;
    console.log('[Nostr] PQ crypto initialized');
    return pqPublicKey;
  } catch (error) {
    console.error('[Nostr] Failed to initialize PQ crypto:', error);
    pqInitialized = false;
    return null;
  }
}

/**
 * Get our PQ public key for sharing
 */
export function getPqPublicKey() {
  return pqPublicKey;
}

/**
 * Register a peer's PQ public key
 */
export function registerPqPeerKey(nostrPubKey, pqPubKeyBase64) {
  pqPeerKeys.set(nostrPubKey, pqPubKeyBase64);
  console.log(`[Nostr] Registered PQ key for peer: ${nostrPubKey.slice(0, 16)}...`);
}

/**
 * Check if a peer supports PQ crypto
 */
export function peerSupportsPq(nostrPubKey) {
  return pqPeerKeys.has(nostrPubKey);
}

/**
 * Generate a new Nostr keypair using real secp256k1
 */
export function generateKeyPair() {
  // Generate 32 random bytes for private key
  const privateKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  const publicKeyBytes = schnorr.getPublicKey(privateKeyBytes);

  return {
    privateKey: nobleToHex(privateKeyBytes),
    publicKey: nobleToHex(publicKeyBytes),
  };
}

/**
 * Get x-only public key hex from private key hex
 */
export function getPublicKeyHex(privateKeyHex) {
  const privBytes = nobleFromHex(privateKeyHex);
  const pubBytes = schnorr.getPublicKey(privBytes);
  return nobleToHex(pubBytes);
}

/**
 * Compute event ID (SHA-256 of NIP-01 serialized event)
 */
function getEventId(event) {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);

  const hash = sha256(new TextEncoder().encode(serialized));
  return nobleToHex(hash);
}

/**
 * Sign event with Schnorr signature (NIP-01)
 */
function signEvent(event, privateKeyHex) {
  const eventIdBytes = nobleFromHex(event.id);
  const privKeyBytes = nobleFromHex(privateKeyHex);
  const sig = schnorr.sign(eventIdBytes, privKeyBytes);
  return nobleToHex(sig);
}

/**
 * Create a signed Nostr event
 */
export function createEvent(kind, content, tags, privateKeyHex) {
  const pubkey = getPublicKeyHex(privateKeyHex);
  const created_at = Math.floor(Date.now() / 1000);

  const event = {
    kind,
    content,
    tags,
    pubkey,
    created_at,
  };

  event.id = getEventId(event);
  event.sig = signEvent(event, privateKeyHex);

  return event;
}

/**
 * Encrypt message for NIP-04 DM using proper ECDH shared secret
 */
export async function encryptDM(message, recipientPubKeyHex, senderPrivKeyHex) {
  // NIP-04 ECDH: prepend 0x02 to x-only pubkey to make compressed point
  const fullPub = new Uint8Array(33);
  fullPub[0] = 0x02;
  fullPub.set(nobleFromHex(recipientPubKeyHex), 1);

  const shared = getSharedSecret(senderPrivKeyHex, fullPub);
  const sharedX = shared.slice(1, 33); // x-coordinate as AES key

  const iv = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    'raw',
    sharedX,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt']
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    key,
    new TextEncoder().encode(message)
  );

  const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  const ivBase64 = btoa(String.fromCharCode(...iv));

  return `${encryptedBase64}?iv=${ivBase64}`;
}

/**
 * Decrypt NIP-04 DM using proper ECDH shared secret
 */
export async function decryptDM(encryptedContent, senderPubKeyHex, recipientPrivKeyHex) {
  const [encryptedBase64, ivPart] = encryptedContent.split('?iv=');

  const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivPart), c => c.charCodeAt(0));

  // NIP-04 ECDH: prepend 0x02 to x-only pubkey
  const fullPub = new Uint8Array(33);
  fullPub[0] = 0x02;
  fullPub.set(nobleFromHex(senderPubKeyHex), 1);

  const shared = getSharedSecret(recipientPrivKeyHex, fullPub);
  const sharedX = shared.slice(1, 33);

  const key = await crypto.subtle.importKey(
    'raw',
    sharedX,
    { name: 'AES-CBC', length: 256 },
    false,
    ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    key,
    encrypted
  );

  return new TextDecoder().decode(decrypted);
}

/**
 * Nostr Relay Connection
 */
export class RelayConnection {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.connected = false;
    this.subscriptions = new Map();
    this.pendingMessages = [];
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.listeners = {
      event: [],
      connect: [],
      disconnect: [],
      error: [],
    };
  }

  on(event, callback) {
    if (this.listeners[event]) {
      this.listeners[event].push(callback);
    }
  }

  off(event, callback) {
    if (this.listeners[event]) {
      const idx = this.listeners[event].indexOf(callback);
      if (idx >= 0) this.listeners[event].splice(idx, 1);
    }
  }

  emit(event, data) {
    if (this.listeners[event]) {
      this.listeners[event].forEach(cb => cb(data));
    }
  }

  connect() {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          console.log(`[Nostr] Connected to ${this.url}`);
          this.connected = true;
          this.reconnectAttempts = 0;

          // Send pending messages
          while (this.pendingMessages.length > 0) {
            const msg = this.pendingMessages.shift();
            this.ws.send(msg);
          }

          this.emit('connect', { url: this.url });
          resolve();
        };

        this.ws.onclose = () => {
          console.log(`[Nostr] Disconnected from ${this.url}`);
          this.connected = false;
          this.emit('disconnect', { url: this.url });
          this.attemptReconnect();
        };

        this.ws.onerror = (error) => {
          console.error(`[Nostr] Error on ${this.url}:`, error);
          this.emit('error', { url: this.url, error });
          reject(error);
        };

        this.ws.onmessage = (msg) => {
          this.handleMessage(msg.data);
        };
      } catch (error) {
        reject(error);
      }
    });
  }

  attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log(`[Nostr] Max reconnect attempts reached for ${this.url}`);
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);

    console.log(`[Nostr] Reconnecting to ${this.url} in ${delay}ms...`);
    setTimeout(() => this.connect().catch(() => {}), delay);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.connected = false;
  }

  send(message) {
    const json = JSON.stringify(message);

    if (this.connected && this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(json);
    } else {
      this.pendingMessages.push(json);
    }
  }

  handleMessage(data) {
    try {
      const message = JSON.parse(data);
      const [type, ...rest] = message;

      switch (type) {
        case 'EVENT': {
          const [subId, event] = rest;
          this.emit('event', { subId, event, relay: this.url });

          const sub = this.subscriptions.get(subId);
          if (sub?.callback) {
            sub.callback(event);
          }
          break;
        }
        case 'OK': {
          const [eventId, success, message] = rest;
          console.log(`[Nostr] OK: ${eventId} - ${success} - ${message}`);
          break;
        }
        case 'EOSE': {
          const [subId] = rest;
          console.log(`[Nostr] End of stored events for ${subId}`);
          break;
        }
        case 'NOTICE': {
          console.log(`[Nostr] Notice from ${this.url}: ${rest[0]}`);
          break;
        }
      }
    } catch (error) {
      console.error('[Nostr] Failed to parse message:', error);
    }
  }

  subscribe(filters, callback) {
    const subId = crypto.randomUUID().replace(/-/g, '').slice(0, 16);

    this.subscriptions.set(subId, { filters, callback });
    this.send(['REQ', subId, ...filters]);

    return subId;
  }

  unsubscribe(subId) {
    this.subscriptions.delete(subId);
    this.send(['CLOSE', subId]);
  }

  publish(event) {
    this.send(['EVENT', event]);
  }
}

/**
 * Nostr Client - manages multiple relay connections
 */
export class NostrClient {
  constructor() {
    this.relays = new Map();
    this.privateKey = null;
    this.publicKey = null;
    this.listeners = {
      event: [],
      message: [],
      connect: [],
      disconnect: [],
    };
  }

  on(event, callback) {
    if (this.listeners[event]) {
      this.listeners[event].push(callback);
    }
  }

  emit(event, data) {
    if (this.listeners[event]) {
      this.listeners[event].forEach(cb => cb(data));
    }
  }

  init(privateKey) {
    if (privateKey) {
      this.privateKey = privateKey;
      this.publicKey = getPublicKeyHex(privateKey);
    } else {
      const keys = generateKeyPair();
      this.privateKey = keys.privateKey;
      this.publicKey = keys.publicKey;
    }

    return {
      privateKey: this.privateKey,
      publicKey: this.publicKey,
    };
  }

  async connectRelays(urls = DEFAULT_RELAYS) {
    const connections = urls.map(async (url) => {
      if (this.relays.has(url)) return;

      const relay = new RelayConnection(url);

      relay.on('event', (data) => {
        this.handleEvent(data);
      });

      relay.on('connect', () => {
        this.emit('connect', { url });
      });

      relay.on('disconnect', () => {
        this.emit('disconnect', { url });
      });

      try {
        await relay.connect();
        this.relays.set(url, relay);
      } catch (error) {
        console.error(`[Nostr] Failed to connect to ${url}:`, error);
      }
    });

    await Promise.allSettled(connections);
    return this.getConnectedRelays();
  }

  getConnectedRelays() {
    return Array.from(this.relays.entries())
      .filter(([, relay]) => relay.connected)
      .map(([url]) => url);
  }

  disconnect() {
    for (const relay of this.relays.values()) {
      relay.disconnect();
    }
    this.relays.clear();
  }

  async handleEvent({ subId, event, relay }) {
    this.emit('event', { subId, event, relay });

    // Handle PQ-encrypted DMs (post-quantum)
    if (event.kind === KIND.PQ_ENCRYPTED_DM) {
      try {
        const senderPubKey = event.pubkey;

        // Extract sender's PQ public key from tags
        const pqTag = event.tags.find(t => t[0] === 'pq');
        if (pqTag && pqTag[1]) {
          registerPqPeerKey(senderPubKey, pqTag[1]);
        }

        // Initialize PQ crypto if needed
        if (!pqInitialized) {
          await initPqCrypto();
        }

        const content = await pqCrypto.parsePqDmContent(
          senderPubKey,
          event.content,
          pqTag ? pqTag[1] : null
        );

        this.emit('message', {
          id: event.id,
          from: senderPubKey,
          to: this.publicKey,
          content,
          timestamp: event.created_at * 1000,
          relay,
          encrypted: true,
          pqEncrypted: true, // Flag for PQ encryption
          tags: event.tags,
        });
      } catch (error) {
        console.error('[Nostr] Failed to decrypt PQ DM:', error);
      }
    }

    // Handle NIP-04 encrypted DMs (legacy)
    if (event.kind === KIND.ENCRYPTED_DM) {
      try {
        const senderPubKey = event.pubkey;
        const content = await decryptDM(event.content, senderPubKey, this.privateKey);

        this.emit('message', {
          id: event.id,
          from: senderPubKey,
          to: this.publicKey,
          content,
          timestamp: event.created_at * 1000,
          relay,
          encrypted: true,
          pqEncrypted: false,
          tags: event.tags,
        });
      } catch (error) {
        console.error('[Nostr] Failed to decrypt NIP-04 DM:', error);
      }
    }
  }

  subscribeToMessages() {
    if (!this.publicKey) {
      throw new Error('Client not initialized');
    }

    const filters = [
      // DMs to us (both NIP-04 and PQ)
      {
        kinds: [KIND.ENCRYPTED_DM, KIND.PQ_ENCRYPTED_DM],
        '#p': [this.publicKey],
      },
      // Our sent DMs (both NIP-04 and PQ)
      {
        kinds: [KIND.ENCRYPTED_DM, KIND.PQ_ENCRYPTED_DM],
        authors: [this.publicKey],
      },
    ];

    for (const relay of this.relays.values()) {
      if (relay.connected) {
        relay.subscribe(filters, null);
      }
    }
  }

  async sendDM(recipientPubKey, message, usePq = true) {
    if (!this.privateKey) {
      throw new Error('Client not initialized');
    }

    let event;

    // Use PQ crypto if available and peer supports it
    if (usePq && pqInitialized && peerSupportsPq(recipientPubKey)) {
      const pqPeerKey = pqPeerKeys.get(recipientPubKey);
      const encrypted = await pqCrypto.createPqDmContent(recipientPubKey, message, pqPeerKey);

      // Include our PQ public key in tags for discovery
      event = createEvent(
        KIND.PQ_ENCRYPTED_DM,
        encrypted,
        [
          ['p', recipientPubKey],
          ['pq', pqPublicKey], // Our PQ public key
        ],
        this.privateKey
      );

      console.log('[Nostr] Sending PQ-encrypted DM');
    } else {
      // Fallback to NIP-04
      const encrypted = await encryptDM(message, recipientPubKey, this.privateKey);

      event = createEvent(
        KIND.ENCRYPTED_DM,
        encrypted,
        [['p', recipientPubKey]],
        this.privateKey
      );

      console.log('[Nostr] Sending NIP-04 encrypted DM (legacy)');
    }

    // Publish to all connected relays
    for (const relay of this.relays.values()) {
      if (relay.connected) {
        relay.publish(event);
      }
    }

    return event;
  }

  /**
   * Send a DM with explicit PQ encryption
   */
  async sendPqDM(recipientPubKey, message, recipientPqPubKey) {
    if (!this.privateKey) {
      throw new Error('Client not initialized');
    }

    if (!pqInitialized) {
      await initPqCrypto();
    }

    // Register their PQ key if provided
    if (recipientPqPubKey) {
      registerPqPeerKey(recipientPubKey, recipientPqPubKey);
    }

    const pqPeerKey = pqPeerKeys.get(recipientPubKey);
    if (!pqPeerKey) {
      throw new Error('No PQ public key for recipient. Provide recipientPqPubKey.');
    }

    const encrypted = await pqCrypto.createPqDmContent(recipientPubKey, message, pqPeerKey);

    const event = createEvent(
      KIND.PQ_ENCRYPTED_DM,
      encrypted,
      [
        ['p', recipientPubKey],
        ['pq', pqPublicKey],
      ],
      this.privateKey
    );

    for (const relay of this.relays.values()) {
      if (relay.connected) {
        relay.publish(event);
      }
    }

    return event;
  }

  async sendNote(content) {
    if (!this.privateKey) {
      throw new Error('Client not initialized');
    }

    const event = createEvent(
      KIND.TEXT_NOTE,
      content,
      [],
      this.privateKey
    );

    for (const relay of this.relays.values()) {
      if (relay.connected) {
        relay.publish(event);
      }
    }

    return event;
  }
}
