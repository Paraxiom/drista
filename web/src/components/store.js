/**
 * Chat Store - Signals-based State Management with Nostr Integration
 *
 * Hybrid IPFS Storage: Content on IPFS, references on-chain
 */

import { signal, computed } from '@preact/signals';
import { NostrClient, DEFAULT_RELAYS, encryptDM, createEvent, KIND, getPublicKeyHex } from '../lib/nostr.js';
import { StarkIdentityManager } from '../lib/stark-identity.js';
import {
  uploadToIPFS,
  fetchFromIPFS,
  hashContent,
  verifyContent,
  isIPFSCid,
  createMessageEnvelope,
  getIPFSStatus,
} from '../lib/ipfs.js';
import * as pqDm from '../lib/pq-dm.js';

// ── Reactive state ──────────────────────────────────────────
export const channels = signal([]);
export const messages = signal({});           // { channelId: Message[] }
export const currentChannelId = signal(null); // string ID
export const nostrStatus = signal('disconnected');
export const connectedRelays = signal([]);
export const activeModal = signal(null);      // null|'newDM'|'newGroup'|'settings'|'relayInfo'
export const ipfsEnabled = signal(true);      // Use IPFS hybrid storage
export const ipfsStatus = signal('ready');    // 'ready'|'uploading'|'error'
export const lastError = signal(null);        // { message: string, timestamp: number } | null
export const sendStatus = signal('idle');     // 'idle'|'sending'|'success'|'error'

// ── Computed ────────────────────────────────────────────────
export const currentChannel = computed(() =>
  channels.value.find(ch => ch.id === currentChannelId.value) || null
);

export const currentMessages = computed(() =>
  messages.value[currentChannelId.value] || []
);

export const transportSecurity = computed(() => {
  const relays = connectedRelays.value;
  const hasLocal = relays.some(r => r.startsWith('ws://localhost'));
  const hasTls = relays.some(r => r.startsWith('wss://'));
  if (hasLocal && !hasTls) return 'PQ-SECURED';
  if (hasLocal && hasTls) return 'HYBRID';
  if (hasTls) return 'TLS';
  return 'NONE';
});

// ── Internal state (not reactive) ───────────────────────────
let starkIdentity = null;
const nostr = new NostrClient();

// ── Nostr listeners ─────────────────────────────────────────
nostr.on('connect', ({ url }) => {
  console.log(`[Store] Relay connected: ${url}`);
  connectedRelays.value = [...nostr.getConnectedRelays()];
  updateNostrStatus();
});

nostr.on('disconnect', ({ url }) => {
  console.log(`[Store] Relay disconnected: ${url}`);
  connectedRelays.value = [...nostr.getConnectedRelays()];
  updateNostrStatus();
});

nostr.on('message', (msg) => {
  console.log('[Store] Received message:', msg);
  handleIncomingMessage(msg);
});

// ── Load persisted state ────────────────────────────────────
load();

// Add default channel if none
if (channels.value.length === 0) {
  addChannel({
    id: '#drista',
    name: '#drista',
    channelType: 'forum',
    encrypted: false,
    pqcEnabled: false,
    unreadCount: 0,
  });
}

// ── Status helpers ──────────────────────────────────────────
function updateNostrStatus() {
  const count = connectedRelays.value.length;
  if (count === 0) {
    nostrStatus.value = 'disconnected';
  } else if (count < 3) {
    nostrStatus.value = 'partial';
  } else {
    nostrStatus.value = 'connected';
  }
}

// ── Nostr init / connect ────────────────────────────────────
export function initNostr() {
  const forceNew = new URLSearchParams(window.location.search).has('newid');
  let privateKey = forceNew ? null : localStorage.getItem('drista_nostr_privkey');

  const keys = nostr.init(privateKey);

  if (!privateKey || forceNew) {
    if (!forceNew) {
      localStorage.setItem('drista_nostr_privkey', keys.privateKey);
    }
  }
  localStorage.setItem('drista_nostr_pubkey', keys.publicKey);

  console.log('[Store] Nostr initialized with pubkey:', keys.publicKey.slice(0, 16) + '...');
  return keys;
}

export async function connectNostr(relays = DEFAULT_RELAYS) {
  nostrStatus.value = 'connecting';

  const connected = await nostr.connectRelays(relays);
  console.log('[Store] Connected to relays:', connected);

  nostr.subscribeToMessages();
  return connected;
}

export function disconnectNostr() {
  nostr.disconnect();
  nostrStatus.value = 'disconnected';
  connectedRelays.value = [];
}

// ── Incoming messages (with IPFS hybrid storage support) ────
export async function handleIncomingMessage(msg) {
  // Determine channel: use msg.channelId for forum messages, or create DM channel
  let channelId;

  // Check if this is a PQ-encrypted message
  const isPqEncrypted = msg.pqEncrypted === true;

  if (msg.channelId) {
    // Forum/channel message - normalize to #channel format
    channelId = msg.channelId.startsWith('#') ? msg.channelId : `#${msg.channelId}`;
    if (!channels.value.find(ch => ch.id === channelId)) {
      addChannel({
        id: channelId,
        name: channelId,
        channelType: 'forum',
        encrypted: false,
        pqcEnabled: false,
        unreadCount: 0,
      });
    }
  } else {
    // DM - create dm:pubkey channel
    channelId = `dm:${msg.from}`;
    if (!channels.value.find(ch => ch.id === channelId)) {
      addChannel({
        id: channelId,
        name: msg.from.slice(0, 12) + '...',
        channelType: 'direct',
        encrypted: true,
        pqcEnabled: isPqEncrypted,
        unreadCount: 0,
        nostrPubkey: msg.from,
      });
    } else if (isPqEncrypted) {
      // Update channel to mark PQC capability discovered
      channels.value = channels.value.map(ch =>
        ch.id === channelId ? { ...ch, pqcEnabled: true } : ch
      );
    }
  }

  // Register sender's PQ key if present in message tags
  const pqTag = msg.tags?.find(t => t[0] === 'pq');
  if (pqTag && pqTag[1]) {
    pqDm.registerPeerKey(msg.from, pqTag[1]);
  }

  // Check if this is an IPFS hybrid message
  let messageContent = msg.content;
  let ipfsCid = null;
  let ipfsVerified = null;

  // Check for IPFS tag or try to parse content as IPFS reference
  const ipfsTag = msg.tags?.find(t => t[0] === 'ipfs');
  if (ipfsTag) {
    ipfsCid = ipfsTag[1];
  } else {
    // Try to parse content as JSON with IPFS reference
    try {
      const parsed = JSON.parse(msg.content);
      if (parsed.ipfs && parsed.v === 2) {
        ipfsCid = parsed.ipfs;
      }
    } catch {
      // Not JSON, use content as-is
    }
  }

  // Fetch from IPFS if we have a CID
  if (ipfsCid) {
    try {
      console.log('[Store] Fetching message from IPFS:', ipfsCid);
      const envelope = await fetchFromIPFS(ipfsCid);
      messageContent = envelope.content || envelope;

      // Verify content hash if available
      const hashTag = msg.tags?.find(t => t[0] === 'content-hash');
      if (hashTag) {
        const expectedHash = hashTag[1];
        const actualHash = await hashContent(messageContent);
        ipfsVerified = actualHash.slice(0, 16) === expectedHash;
        console.log(`[Store] IPFS content verification: ${ipfsVerified ? 'VALID' : 'INVALID'}`);
      } else {
        ipfsVerified = true; // No hash to verify against
      }
    } catch (error) {
      console.warn('[Store] Failed to fetch from IPFS, using on-chain content:', error);
      // Fall back to on-chain content (might be truncated/reference)
      ipfsVerified = false;
    }
  }

  // STARK verification
  let starkProof = null;
  let starkPubkey = null;
  let starkVerified = null;

  const starkTag = msg.tags?.find(t => t[0] === 'stark-proof');
  if (starkTag) {
    starkProof = starkTag[1];
    starkPubkey = starkTag[2];
    try {
      starkVerified = StarkIdentityManager.verify(starkProof, messageContent, starkPubkey);
      console.log(`[Store] STARK verification: ${starkVerified ? 'VALID' : 'INVALID'}`);
    } catch (error) {
      console.warn('[Store] STARK verification failed:', error);
      starkVerified = false;
    }
  }

  const message = {
    id: msg.id,
    sender: msg.from,
    recipient: msg.to,
    text: messageContent,
    timestamp: msg.timestamp,
    encrypted: msg.encrypted,
    pqcVerified: isPqEncrypted, // PQC badge flag
    relay: msg.relay,
    fromNostr: true,
    starkProof,
    starkPubkey,
    starkVerified,
    ipfsCid,
    ipfsVerified,
  };

  const old = messages.value[channelId] || [];
  // Deduplicate: check both local ID and nostrEventId (for messages we sent that echo back)
  if (old.find(m => m.id === msg.id || m.nostrEventId === msg.id)) return; // duplicate

  // Immutable update
  messages.value = { ...messages.value, [channelId]: [...old, message] };

  // Unread count
  if (currentChannelId.value !== channelId) {
    channels.value = channels.value.map(ch =>
      ch.id === channelId ? { ...ch, unreadCount: (ch.unreadCount || 0) + 1 } : ch
    );
  }

  save();
}

// ── Send public channel message (with IPFS hybrid storage) ──
export async function sendChannelMessage(channelId, messageText, starkSig) {
  try {
    const tags = [['e', channelId.replace('#', ''), '', 'root']];
    if (starkSig) {
      tags.push(['stark-proof', starkSig.proof, starkSig.pubkey]);
    }

    let contentForChain = messageText;
    let ipfsCid = null;

    // Use IPFS hybrid storage if enabled
    if (ipfsEnabled.value) {
      try {
        ipfsStatus.value = 'uploading';

        // Create message envelope with metadata
        const envelope = createMessageEnvelope(
          messageText,
          nostr.publicKey,
          channelId
        );

        // Upload to IPFS
        ipfsCid = await uploadToIPFS(envelope);
        const contentHash = await hashContent(messageText);

        // On-chain: only store CID and hash (much smaller!)
        contentForChain = JSON.stringify({
          ipfs: ipfsCid,
          hash: contentHash.slice(0, 16), // Truncated hash for verification
          v: 2, // Version 2 = IPFS hybrid
        });

        tags.push(['ipfs', ipfsCid]);
        tags.push(['content-hash', contentHash.slice(0, 16)]);

        ipfsStatus.value = 'ready';
        console.log('[Store] Message uploaded to IPFS:', ipfsCid);
      } catch (ipfsError) {
        console.warn('[Store] IPFS upload failed, falling back to on-chain:', ipfsError);
        ipfsStatus.value = 'error';
        // Fall back to storing full message on-chain
      }
    }

    const event = createEvent(
      KIND.CHANNEL_MESSAGE,  // kind 42
      contentForChain,
      tags,
      nostr.privateKey
    );

    console.log('[Store] Sending channel message:', event.id, 'to', channelId, ipfsCid ? `(IPFS: ${ipfsCid})` : '(on-chain)');

    for (const relay of nostr.relays.values()) {
      if (relay.connected) {
        relay.publish(event);
      }
    }

    // Add IPFS CID to returned event for reference
    if (ipfsCid) {
      event.ipfsCid = ipfsCid;
    }

    return event;
  } catch (error) {
    console.error('[Store] Failed to send channel message:', error);
    ipfsStatus.value = 'error';
    throw error;
  }
}

// ── Send Nostr DM ───────────────────────────────────────────
export async function sendNostrDM(recipientPubKey, messageText, starkSig) {
  try {
    const tags = [['p', recipientPubKey]];
    if (starkSig) {
      tags.push(['stark-proof', starkSig.proof, starkSig.pubkey]);
    }

    let event;

    // Check if recipient has PQ key - use PQC encryption if available
    if (pqDm.isPqDmReady() && pqDm.hasPqKey(recipientPubKey)) {
      // PQC path: ML-KEM-768 + AES-256-GCM
      const { content, senderEk } = await pqDm.encryptPqDm(recipientPubKey, messageText);

      // Add our EK to tags for key discovery
      tags.push(['pq', senderEk]);

      event = createEvent(
        KIND.PQ_ENCRYPTED_DM,
        content,
        tags,
        nostr.privateKey
      );

      console.log('[Store] Sending PQC-encrypted DM:', event.id);
    } else {
      // Fallback to NIP-04 (legacy secp256k1)
      const ciphertext = await encryptDM(messageText, recipientPubKey, nostr.privateKey);

      event = createEvent(
        KIND.ENCRYPTED_DM,
        ciphertext,
        tags,
        nostr.privateKey
      );

      console.log('[Store] Sending NIP-04 DM (legacy):', event.id);
    }

    for (const relay of nostr.relays.values()) {
      if (relay.connected) {
        relay.publish(event);
      }
    }

    return event;
  } catch (error) {
    console.error('[Store] Failed to send DM:', error);
    throw error;
  }
}

// ── PQ-DM initialization ────────────────────────────────────
export async function initPqDm() {
  try {
    await pqDm.initPqDm();
    console.log('[Store] PQ-DM initialized');
    return true;
  } catch (error) {
    console.warn('[Store] PQ-DM initialization failed:', error);
    return false;
  }
}

export async function publishPqKey() {
  if (!pqDm.isPqDmReady()) {
    console.warn('[Store] PQ-DM not ready, cannot publish key');
    return null;
  }
  try {
    const event = await pqDm.publishPqKey(nostr);
    console.log('[Store] Published PQ key');
    return event;
  } catch (error) {
    console.error('[Store] Failed to publish PQ key:', error);
    return null;
  }
}

export function isPqDmReady() {
  return pqDm.isPqDmReady();
}

export function hasPqKey(pubkey) {
  return pqDm.hasPqKey(pubkey);
}

export async function fetchPqKey(pubkey) {
  return pqDm.fetchPqKey(nostr, pubkey);
}

// ── STARK identity ──────────────────────────────────────────
export function setStarkIdentity(si) {
  starkIdentity = si;
  console.log('[Store] STARK identity set, fingerprint:', si.fingerprint);
}

export function signWithStark(text) {
  if (!starkIdentity) return null;
  try {
    const proof = starkIdentity.signEvent(text);
    return { proof, pubkey: starkIdentity.pubkeyHex };
  } catch (error) {
    console.warn('[Store] STARK signing failed:', error);
    return null;
  }
}

// ── Nostr public key accessor ───────────────────────────────
export function getNostrPublicKey() {
  return nostr.publicKey;
}

// ── Persistence ─────────────────────────────────────────────
export function load() {
  try {
    const stored = localStorage.getItem('drista_store');
    if (stored) {
      const data = JSON.parse(stored);
      channels.value = data.channels || [];
      messages.value = data.messages || {};
    }
  } catch (error) {
    console.error('[Store] Failed to load:', error);
  }
}

export function save() {
  try {
    localStorage.setItem('drista_store', JSON.stringify({
      channels: channels.value,
      messages: messages.value,
    }));
  } catch (error) {
    console.error('[Store] Failed to save:', error);
  }
}

// ── Channel operations ──────────────────────────────────────
export function addChannel(channel) {
  if (channels.value.find(ch => ch.id === channel.id)) return;

  channels.value = [...channels.value, channel];
  if (!messages.value[channel.id]) {
    messages.value = { ...messages.value, [channel.id]: [] };
  }
  save();
}

export function removeChannel(id) {
  const ch = channels.value.find(c => c.id === id);
  if (!ch) return;

  channels.value = channels.value.filter(c => c.id !== id);
  const newMsgs = { ...messages.value };
  delete newMsgs[id];
  messages.value = newMsgs;

  if (currentChannelId.value === id) {
    currentChannelId.value = null;
  }
  save();
}

export function setCurrentChannel(id) {
  const ch = channels.value.find(c => c.id === id);
  if (ch) {
    currentChannelId.value = id;
  }
}

export function getChannel(id) {
  return channels.value.find(ch => ch.id === id);
}

export async function addMessage(channelId, message) {
  // Sign with STARK proof if available
  const starkSig = signWithStark(message.text);
  if (starkSig) {
    message.starkProof = starkSig.proof;
    message.starkPubkey = starkSig.pubkey;
  }

  const channel = getChannel(channelId);

  // Send via Nostr
  if (nostrStatus.value !== 'disconnected') {
    sendStatus.value = 'sending';
    try {
      let event;
      if (channel?.nostrPubkey) {
        // DM channel - send encrypted
        // Check if we'll use PQC for this message
        const willUsePqc = pqDm.isPqDmReady() && pqDm.hasPqKey(channel.nostrPubkey);
        event = await sendNostrDM(channel.nostrPubkey, message.text, starkSig);
        message.pqcVerified = willUsePqc; // Mark outgoing messages with PQC flag
      } else if (channel?.channelType === 'forum') {
        // Public forum channel - send as channel message
        event = await sendChannelMessage(channelId, message.text, starkSig);
      }
      if (event) {
        message.nostrEventId = event.id;
        message.sentViaNostr = true;
        sendStatus.value = 'success';
        // Clear success status after 2 seconds
        setTimeout(() => { if (sendStatus.value === 'success') sendStatus.value = 'idle'; }, 2000);
      }
    } catch (error) {
      console.error('[Store] Failed to send via Nostr:', error);
      message.sentViaNostr = false;
      sendStatus.value = 'error';
      lastError.value = {
        message: `Failed to send message: ${error.message || 'Network error'}`,
        timestamp: Date.now(),
      };
      // Clear error status after 5 seconds
      setTimeout(() => { if (sendStatus.value === 'error') sendStatus.value = 'idle'; }, 5000);
    }
  } else {
    // Not connected - show error
    sendStatus.value = 'error';
    lastError.value = {
      message: 'Not connected to any relay. Message saved locally.',
      timestamp: Date.now(),
    };
    message.sentViaNostr = false;
  }

  const old = messages.value[channelId] || [];
  messages.value = { ...messages.value, [channelId]: [...old, message] };

  // Unread if not current
  if (currentChannelId.value !== channelId && channel) {
    channels.value = channels.value.map(ch =>
      ch.id === channelId ? { ...ch, unreadCount: (ch.unreadCount || 0) + 1 } : ch
    );
  }

  save();
}

export function markRead(channelId) {
  const ch = channels.value.find(c => c.id === channelId);
  if (ch && ch.unreadCount > 0) {
    channels.value = channels.value.map(c =>
      c.id === channelId ? { ...c, unreadCount: 0 } : c
    );
    save();
  }
}

/**
 * Clear all messages from local view (doesn't delete from relay)
 * Admin function - Ctrl+Shift+K to trigger
 */
export function clearAllMessages() {
  messages.value = {};
  localStorage.removeItem('drista_messages');
  console.log('[Store] Cleared all local messages');
}

/**
 * Clear messages for a specific channel
 */
export function clearChannelMessages(channelId) {
  const current = { ...messages.value };
  delete current[channelId];
  messages.value = current;
  save();
  console.log(`[Store] Cleared messages for channel: ${channelId}`);
}
