/**
 * NIP-01 Bridge: QuantumHarmony Nodes as Nostr Relays
 *
 * Speaks standard NIP-01 WebSocket to browser clients and translates
 * events to/from the Mesh Forum pallet via the node's JSON-RPC endpoint.
 *
 * Hybrid mode: events stored in-memory for instant local delivery
 * AND posted to chain for cross-node persistence.
 *
 * Usage:
 *   BRIDGE_PORT=7777 RPC_URL=ws://127.0.0.1:9944 node index.js
 */

import { WebSocketServer, WebSocket } from 'ws';

// ─── Configuration ───────────────────────────────────────────────────────────

const BRIDGE_HOST = process.env.BRIDGE_HOST || '127.0.0.1';
const BRIDGE_PORT = parseInt(process.env.BRIDGE_PORT || '7777', 10);
const RPC_URL = process.env.RPC_URL || 'ws://127.0.0.1:9944';
const CHUNK_DATA_SIZE = 400;          // payload per chunk (leaves room for envelope)
const FORUM_MSG_LIMIT = 512;          // Mesh Forum MaxMessageLength
const POLL_INTERVAL_MS = 12_000;      // fallback poll interval

// ─── Section A: Substrate RPC Client ─────────────────────────────────────────

let rpcWs = null;
let rpcId = 0;
let rpcConnected = false;
let rpcReconnectDelay = 1000;
const rpcPending = new Map();         // id -> { resolve, reject }

function rpcSend(method, params = []) {
  return new Promise((resolve, reject) => {
    if (!rpcConnected || !rpcWs) {
      reject(new Error('RPC not connected'));
      return;
    }
    const id = ++rpcId;
    rpcPending.set(id, { resolve, reject });
    rpcWs.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
  });
}

function connectRpc() {
  return new Promise((resolve) => {
    try {
      rpcWs = new WebSocket(RPC_URL);
    } catch (err) {
      console.warn(`[Bridge] Cannot create RPC socket: ${err.message}`);
      rpcConnected = false;
      resolve(false);
      return;
    }

    rpcWs.on('open', () => {
      console.log(`[Bridge] RPC connected to ${RPC_URL}`);
      rpcConnected = true;
      rpcReconnectDelay = 1000;
      resolve(true);
    });

    rpcWs.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw);
        // Subscription notification
        if (msg.method && msg.params) {
          handleRpcSubscription(msg);
          return;
        }
        const pending = rpcPending.get(msg.id);
        if (pending) {
          rpcPending.delete(msg.id);
          if (msg.error) pending.reject(new Error(msg.error.message));
          else pending.resolve(msg.result);
        }
      } catch { /* ignore parse errors */ }
    });

    rpcWs.on('close', () => {
      rpcConnected = false;
      console.warn(`[Bridge] RPC disconnected, reconnecting in ${rpcReconnectDelay}ms...`);
      setTimeout(() => {
        rpcReconnectDelay = Math.min(rpcReconnectDelay * 2, 30_000);
        connectRpc();
      }, rpcReconnectDelay);
    });

    rpcWs.on('error', (err) => {
      console.warn(`[Bridge] RPC error: ${err.message}`);
      rpcConnected = false;
      resolve(false);
    });
  });
}

// ─── Section B: Chunking ─────────────────────────────────────────────────────

function chunkEvent(eventJson, eventId) {
  const groupId = eventId.slice(0, 12);
  const chunks = [];
  for (let i = 0; i < eventJson.length; i += CHUNK_DATA_SIZE) {
    chunks.push(eventJson.slice(i, i + CHUNK_DATA_SIZE));
  }
  return chunks.map((data, ci) => JSON.stringify({
    cg: groupId,
    ci,
    ct: chunks.length,
    d: data,
  }));
}

// chunkGroup: groupId -> { total, parts: Map(index -> data) }
const chunkGroups = new Map();

function reassembleChunk(parsed) {
  const { cg, ci, ct, d } = parsed;
  if (!chunkGroups.has(cg)) {
    chunkGroups.set(cg, { total: ct, parts: new Map() });
  }
  const group = chunkGroups.get(cg);
  group.parts.set(ci, d);

  if (group.parts.size === group.total) {
    chunkGroups.delete(cg);
    let full = '';
    for (let i = 0; i < group.total; i++) {
      full += group.parts.get(i);
    }
    return full;
  }
  return null; // not yet complete
}

function isChunkEnvelope(content) {
  try {
    const p = JSON.parse(content);
    return p && typeof p.cg === 'string' && typeof p.ci === 'number' && typeof p.ct === 'number';
  } catch {
    return false;
  }
}

// ─── Section C: Chain Sync ───────────────────────────────────────────────────

let lastKnownCount = 0;
let chainSyncActive = false;

async function postToChain(eventJson) {
  if (!rpcConnected) return;
  try {
    const bytes = new TextEncoder().encode(eventJson);
    if (bytes.length <= FORUM_MSG_LIMIT) {
      await rpcSend('forum_postMessage', [{ content: eventJson }]);
    } else {
      // Need chunking
      const event = JSON.parse(eventJson);
      const chunks = chunkEvent(eventJson, event.id);
      for (const chunk of chunks) {
        await rpcSend('forum_postMessage', [{ content: chunk }]);
      }
    }
  } catch (err) {
    console.warn(`[Bridge] Chain post failed: ${err.message}`);
  }
}

async function pollChainMessages() {
  if (!rpcConnected) return;
  try {
    const countResult = await rpcSend('forum_getMessageCount', []);
    const count = typeof countResult === 'number' ? countResult : parseInt(countResult, 10);
    if (isNaN(count) || count <= lastKnownCount) return;

    const delta = count - lastKnownCount;
    const messages = await rpcSend('forum_getMessages', [delta, lastKnownCount]);
    lastKnownCount = count;

    if (!Array.isArray(messages)) return;

    for (const msg of messages) {
      const content = typeof msg === 'object' ? msg.content : msg;
      processForumMessage(content);
    }
  } catch (err) {
    console.warn(`[Bridge] Chain poll failed: ${err.message}`);
  }
}

function processForumMessage(content) {
  if (typeof content !== 'string') return;

  let eventJson = content;

  // Check if it's a chunk
  if (isChunkEnvelope(content)) {
    const assembled = reassembleChunk(JSON.parse(content));
    if (!assembled) return; // waiting for more chunks
    eventJson = assembled;
  }

  try {
    const event = JSON.parse(eventJson);
    if (!event || !event.id) return;
    if (events.has(event.id)) return; // deduplicate

    events.set(event.id, event);
    broadcastToSubscribers(event);
  } catch { /* not a valid Nostr event */ }
}

function handleRpcSubscription(msg) {
  // chain_subscribeNewHeads notification
  if (msg.method === 'chain_newHead' || msg.method === 'chain_finalizedHead') {
    pollChainMessages();
  }
}

async function startChainSync() {
  if (!rpcConnected) return;
  chainSyncActive = true;

  // Load existing messages into memory
  try {
    const countResult = await rpcSend('forum_getMessageCount', []);
    const count = typeof countResult === 'number' ? countResult : parseInt(countResult, 10);
    if (!isNaN(count) && count > 0) {
      const messages = await rpcSend('forum_getMessages', [count, 0]);
      if (Array.isArray(messages)) {
        for (const msg of messages) {
          const content = typeof msg === 'object' ? msg.content : msg;
          processForumMessage(content);
        }
      }
      lastKnownCount = count;
      console.log(`[Bridge] Loaded ${events.size} events from chain (${count} forum messages)`);
    }
  } catch (err) {
    console.warn(`[Bridge] Failed to load chain history: ${err.message}`);
  }

  // Subscribe to new block headers
  try {
    await rpcSend('chain_subscribeNewHeads', []);
  } catch (err) {
    console.warn(`[Bridge] Block subscription failed: ${err.message}`);
  }

  // Fallback poll timer
  setInterval(() => {
    if (rpcConnected) pollChainMessages();
  }, POLL_INTERVAL_MS);
}

// ─── Section D: NIP-01 WebSocket Server ──────────────────────────────────────

const events = new Map();              // eventId -> event
const subscriptions = new Map();       // ws -> Map(subId -> filters[])

function handleEvent(sender, event) {
  if (!event || !event.id) {
    sender.send(JSON.stringify(['NOTICE', 'invalid event']));
    return;
  }

  const isNew = !events.has(event.id);
  events.set(event.id, event);

  // Acknowledge immediately
  sender.send(JSON.stringify(['OK', event.id, true, '']));

  if (!isNew) return;

  // Broadcast to all local subscribers
  broadcastToSubscribers(event);

  // Async post to chain (fire-and-forget)
  const eventJson = JSON.stringify(event);
  postToChain(eventJson);
}

function handleReq(ws, subId, filters) {
  if (!subId || !Array.isArray(filters)) {
    ws.send(JSON.stringify(['NOTICE', 'invalid REQ']));
    return;
  }

  const subs = subscriptions.get(ws);
  if (subs) subs.set(subId, filters);

  // Send matching stored events
  const matched = [];
  for (const event of events.values()) {
    if (matchesAny(event, filters)) {
      matched.push(event);
    }
  }

  // Sort by created_at descending, apply smallest limit
  matched.sort((a, b) => b.created_at - a.created_at);

  let limit = Infinity;
  for (const f of filters) {
    if (typeof f.limit === 'number' && f.limit < limit) limit = f.limit;
  }

  const toSend = limit < Infinity ? matched.slice(0, limit) : matched;
  for (const event of toSend) {
    ws.send(JSON.stringify(['EVENT', subId, event]));
  }

  ws.send(JSON.stringify(['EOSE', subId]));
}

function handleClose(ws, subId) {
  const subs = subscriptions.get(ws);
  if (subs) subs.delete(subId);
}

function broadcastToSubscribers(event) {
  for (const [ws, subs] of subscriptions) {
    if (ws.readyState !== WebSocket.OPEN) continue;
    for (const [subId, filters] of subs) {
      if (matchesAny(event, filters)) {
        ws.send(JSON.stringify(['EVENT', subId, event]));
      }
    }
  }
}

// ─── Section E: Filter Matching (NIP-01) ─────────────────────────────────────

function matchesAny(event, filters) {
  return filters.some((f) => matchesFilter(event, f));
}

function matchesFilter(event, filter) {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.since && event.created_at < filter.since) return false;
  if (filter.until && event.created_at > filter.until) return false;

  // Tag filters: #p, #e, etc.
  for (const key of Object.keys(filter)) {
    if (key.startsWith('#') && key.length === 2) {
      const tagName = key[1];
      const wanted = filter[key];
      if (!Array.isArray(wanted)) continue;
      const eventTagValues = (event.tags || [])
        .filter((t) => t[0] === tagName)
        .map((t) => t[1]);
      if (!wanted.some((v) => eventTagValues.includes(v))) return false;
    }
  }

  return true;
}

// ─── Section F: Startup ──────────────────────────────────────────────────────

const wss = new WebSocketServer({ host: BRIDGE_HOST, port: BRIDGE_PORT });

wss.on('connection', (ws) => {
  subscriptions.set(ws, new Map());

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      ws.send(JSON.stringify(['NOTICE', 'invalid JSON']));
      return;
    }

    if (!Array.isArray(msg) || msg.length < 2) {
      ws.send(JSON.stringify(['NOTICE', 'invalid message']));
      return;
    }

    const [type, ...rest] = msg;

    switch (type) {
      case 'EVENT':
        handleEvent(ws, rest[0]);
        break;
      case 'REQ':
        handleReq(ws, rest[0], rest.slice(1));
        break;
      case 'CLOSE':
        handleClose(ws, rest[0]);
        break;
      default:
        ws.send(JSON.stringify(['NOTICE', `unknown message type: ${type}`]));
    }
  });

  ws.on('close', () => {
    subscriptions.delete(ws);
  });
});

// Connect to RPC and start
(async () => {
  const rpcOk = await connectRpc();

  if (rpcOk) {
    await startChainSync();
    console.log(`[Bridge] Ready - ws://${BRIDGE_HOST}:${BRIDGE_PORT} ↔ ${RPC_URL}`);
  } else {
    console.log(`[Bridge] Ready - ws://${BRIDGE_HOST}:${BRIDGE_PORT} (in-memory only, no chain backend)`);
    console.log(`[Bridge] Will keep trying to connect to ${RPC_URL}...`);
  }
})();
