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
import * as pqDm from './pq-dm.js';

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
  PQ_ENCRYPTED_DM: 20004, // Post-Quantum encrypted DM (ML-KEM-1024 + AES-256-GCM)
  PQ_KEY: 30078,          // PQ key publication (NIP-33 replaceable, d=ml-kem-1024)
};

// PQ crypto state
let pqInitialized = false;
let pqPublicKey = null;

// Mapping of Nostr pubkeys to PQ public keys (discovered via metadata or handshake)
const pqPeerKeys = new Map();

// Default relays — QuantumHarmony validators + public fallbacks
// Each relay connects to a different validator node for decentralization
export const DEFAULT_RELAYS = [
  'wss://drista.paraxiom.org/ws',         // Alice (Montreal) — Primary relay
  'wss://relay.damus.io',                 // Public fallback — high availability
  'wss://nos.lol',                        // Public fallback — high availability
];

// Additional relays to try if primary fails
export const FALLBACK_RELAYS = [
  'wss://relay.nostr.band',
  'wss://relay.snort.social',
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
    this.maxReconnectAttempts = 10; // Increased from 5 for better resilience
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
          // Log DM events at the earliest point
          if (event.kind === 4 || event.kind === 20004) {
            console.log('[Nostr] RAW DM received! Kind:', event.kind, 'from:', event.pubkey?.slice(0, 12), 'subId:', subId);
          }
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

    // Log what we're subscribing to
    const dmFilter = filters.find(f => f.kinds?.includes(4));
    if (dmFilter) {
      console.log('[Nostr] Subscribing to DMs with filter:', JSON.stringify(dmFilter));
    }

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
    // Log all incoming events for debugging
    if (event.kind === KIND.ENCRYPTED_DM || event.kind === KIND.PQ_ENCRYPTED_DM) {
      console.log('[Nostr] Received DM event! Kind:', event.kind, 'from:', event.pubkey.slice(0, 12), 'subId:', subId);
    }

    this.emit('event', { subId, event, relay });

    // Handle PQ key publications (kind 30078)
    if (event.kind === KIND.PQ_KEY) {
      const ekTag = event.tags.find(t => t[0] === 'ek');
      const dTag = event.tags.find(t => t[0] === 'd');
      if (dTag && dTag[1] === 'ml-kem-1024' && ekTag && ekTag[1]) {
        registerPqPeerKey(event.pubkey, ekTag[1]);
        console.log('[Nostr] Discovered PQ key for:', event.pubkey.slice(0, 16) + '...');
      }
    }

    // Handle PQ-encrypted DMs (post-quantum ML-KEM-1024 + AES-256-GCM)
    if (event.kind === KIND.PQ_ENCRYPTED_DM) {
      try {
        const senderPubKey = event.pubkey;
        const pTag = event.tags.find(t => t[0] === 'p');
        const recipientPubKey = pTag ? pTag[1] : null;

        // Skip our own sent messages (already added locally)
        if (senderPubKey === this.publicKey) {
          console.log('[Nostr] Skipping own PQ DM echo:', event.id.slice(0, 16));
          return;
        }

        // Extract sender's PQ encapsulation key from tags
        const pqTag = event.tags.find(t => t[0] === 'pq');
        if (pqTag && pqTag[1]) {
          // Register for future messages
          registerPqPeerKey(senderPubKey, pqTag[1]);
          pqDm.registerPeerKey(senderPubKey, pqTag[1]);
        }

        // Initialize PQ-DM if needed
        if (!pqDm.isPqDmReady()) {
          await pqDm.initPqDm();
        }

        // Decrypt using ML-KEM-1024 + AES-256-GCM
        const content = await pqDm.decryptPqDm(senderPubKey, event.content);

        this.emit('message', {
          id: event.id,
          from: senderPubKey,
          to: recipientPubKey || this.publicKey,
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
      console.log('[Nostr] Processing NIP-04 DM:', event.id.slice(0, 16), 'from:', event.pubkey.slice(0, 12));
      try {
        const senderPubKey = event.pubkey;
        const pTag = event.tags.find(t => t[0] === 'p');
        const recipientPubKey = pTag ? pTag[1] : null;
        console.log('[Nostr] DM recipient:', recipientPubKey?.slice(0, 12), 'our pubkey:', this.publicKey?.slice(0, 12));

        // Skip our own sent messages (already added locally)
        if (senderPubKey === this.publicKey) {
          console.log('[Nostr] Skipping own NIP-04 DM echo:', event.id.slice(0, 16));
          return;
        }

        console.log('[Nostr] Attempting decryption...');
        const content = await decryptDM(event.content, senderPubKey, this.privateKey);
        console.log('[Nostr] Decrypted successfully, content length:', content.length);

        this.emit('message', {
          id: event.id,
          from: senderPubKey,
          to: recipientPubKey || this.publicKey,
          content,
          timestamp: event.created_at * 1000,
          relay,
          encrypted: true,
          pqEncrypted: false,
          tags: event.tags,
        });
      } catch (error) {
        console.error('[Nostr] Failed to decrypt NIP-04 DM:', error.message || error);
        console.error('[Nostr] DM content preview:', event.content?.slice(0, 50));
      }
    }

    // Handle public text notes (KIND 1) - only from our relay or tagged #drista
    if (event.kind === KIND.TEXT_NOTE) {
      // Filter: only accept from our relay OR tagged with #drista
      const hasTag = event.tags?.some(t => t[0] === 't' && t[1] === 'drista');
      const isOurRelay = relay.includes('drista.paraxiom.org');

      if (hasTag || isOurRelay) {
        this.emit('message', {
          id: event.id,
          from: event.pubkey,
          to: null,
          content: event.content,
          timestamp: event.created_at * 1000,
          relay,
          encrypted: false,
          pqEncrypted: false,
          tags: event.tags,
          channelId: '#drista',
        });
      }
    }

    // Handle channel messages (KIND 42)
    if (event.kind === KIND.CHANNEL_MESSAGE) {
      const channelTag = event.tags.find(t => t[0] === 'e');
      const channelId = channelTag ? channelTag[1] : '#drista';

      this.emit('message', {
        id: event.id,
        from: event.pubkey,
        to: null,
        content: event.content,
        timestamp: event.created_at * 1000,
        relay,
        encrypted: false,
        pqEncrypted: false,
        tags: event.tags,
        channelId,
      });
    }
  }

  subscribeToMessages(starkPubkey = null) {
    console.log('[Nostr] ====== subscribeToMessages CALLED ======');
    if (!this.publicKey) {
      console.log('[Nostr] ERROR: Client not initialized, no publicKey');
      throw new Error('Client not initialized');
    }

    console.log('[Nostr] Nostr transport pubkey:', this.publicKey);
    console.log('[Nostr] STARK pubkey:', starkPubkey);

    // Build list of pubkeys to subscribe for DMs (both Nostr and STARK if different)
    const dmPubkeys = [this.publicKey];
    if (starkPubkey && starkPubkey !== this.publicKey) {
      dmPubkeys.push(starkPubkey);
      console.log('[Nostr] Will subscribe to DMs for BOTH pubkeys');
    }

    const filters = [
      // DMs to us - PQ-encrypted only (FULL PQC: no classical NIP-04)
      {
        kinds: [KIND.PQ_ENCRYPTED_DM],
        '#p': dmPubkeys,
      },
      // Our sent DMs - PQ-encrypted only
      {
        kinds: [KIND.PQ_ENCRYPTED_DM],
        authors: [this.publicKey],
      },
      // PQ key publications (for key discovery)
      {
        kinds: [KIND.PQ_KEY],
        '#d': ['ml-kem-1024'],
      },
    ];

    console.log('[Nostr] DM filters:', JSON.stringify(filters.slice(0, 2)));

    // Only subscribe to public notes on our own relay (drista.paraxiom.org)
    // This prevents flooding from public relays like damus.io
    console.log('[Nostr] Connected relays:', Array.from(this.relays.entries()).map(([url, r]) => `${url}:${r.connected}`));
    for (const relay of this.relays.values()) {
      console.log('[Nostr] Checking relay:', relay.url, 'connected:', relay.connected);
      if (relay.connected) {
        if (relay.url.includes('drista.paraxiom.org')) {
          console.log('[Nostr] Setting up FULL subscription on drista relay');
          // On our own relay, subscribe to channel messages too
          relay.subscribe([
            ...filters,
            {
              kinds: [KIND.TEXT_NOTE, KIND.CHANNEL_MESSAGE],
              '#t': ['drista'], // Only messages tagged with #drista
              limit: 50,
            },
          ], null);
        } else {
          console.log('[Nostr] Setting up DM-only subscription on:', relay.url);
          // On public relays, only subscribe to DMs
          relay.subscribe(filters, null);
        }
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

  async sendNote(content, channelTag = 'drista') {
    if (!this.privateKey) {
      throw new Error('Client not initialized');
    }

    const event = createEvent(
      KIND.TEXT_NOTE,
      content,
      [['t', channelTag]], // Tag with channel for filtering
      this.privateKey
    );

    // Only publish to our relay for channel messages
    for (const relay of this.relays.values()) {
      if (relay.connected && relay.url.includes('drista.paraxiom.org')) {
        relay.publish(event);
      }
    }

    return event;
  }
}
