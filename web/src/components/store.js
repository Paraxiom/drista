/**
 * Chat Store - Signals-based State Management with Nostr Integration
 */

import { signal, computed } from '@preact/signals';
import { NostrClient, DEFAULT_RELAYS, encryptDM, createEvent, KIND, getPublicKeyHex } from '../lib/nostr.js';
import { StarkIdentityManager } from '../lib/stark-identity.js';

// ── Reactive state ──────────────────────────────────────────
export const channels = signal([]);
export const messages = signal({});           // { channelId: Message[] }
export const currentChannelId = signal(null); // string ID
export const nostrStatus = signal('disconnected');
export const connectedRelays = signal([]);
export const activeModal = signal(null);      // null|'newDM'|'newGroup'|'settings'|'relayInfo'

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

// ── Incoming messages ───────────────────────────────────────
export async function handleIncomingMessage(msg) {
  // Determine channel: use msg.channelId for forum messages, or create DM channel
  let channelId;

  if (msg.channelId) {
    // Forum/channel message
    channelId = msg.channelId;
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
        pqcEnabled: false,
        unreadCount: 0,
        nostrPubkey: msg.from,
      });
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
      starkVerified = StarkIdentityManager.verify(starkProof, msg.content, starkPubkey);
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
    text: msg.content,
    timestamp: msg.timestamp,
    encrypted: msg.encrypted,
    relay: msg.relay,
    fromNostr: true,
    starkProof,
    starkPubkey,
    starkVerified,
  };

  const old = messages.value[channelId] || [];
  if (old.find(m => m.id === msg.id)) return; // duplicate

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

// ── Send public channel message ─────────────────────────────
export async function sendChannelMessage(channelId, messageText, starkSig) {
  try {
    const tags = [['e', channelId.replace('#', ''), '', 'root']];
    if (starkSig) {
      tags.push(['stark-proof', starkSig.proof, starkSig.pubkey]);
    }

    const event = createEvent(
      KIND.CHANNEL_MESSAGE,  // kind 42
      messageText,
      tags,
      nostr.privateKey
    );

    console.log('[Store] Sending channel message:', event.id, 'to', channelId);

    for (const relay of nostr.relays.values()) {
      if (relay.connected) {
        relay.publish(event);
      }
    }

    return event;
  } catch (error) {
    console.error('[Store] Failed to send channel message:', error);
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

    const ciphertext = await encryptDM(messageText, recipientPubKey, nostr.privateKey);

    const event = createEvent(
      KIND.ENCRYPTED_DM,
      ciphertext,
      tags,
      nostr.privateKey
    );

    console.log('[Store] Sending DM event:', event.id);

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
    try {
      let event;
      if (channel?.nostrPubkey) {
        // DM channel - send encrypted
        event = await sendNostrDM(channel.nostrPubkey, message.text, starkSig);
      } else if (channel?.channelType === 'forum') {
        // Public forum channel - send as channel message
        event = await sendChannelMessage(channelId, message.text, starkSig);
      }
      if (event) {
        message.nostrEventId = event.id;
        message.sentViaNostr = true;
      }
    } catch (error) {
      console.error('[Store] Failed to send via Nostr, storing locally:', error);
      message.sentViaNostr = false;
    }
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
