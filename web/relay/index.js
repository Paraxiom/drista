/**
 * Minimal NIP-01 Nostr Relay for local development
 * In-memory event store, no persistence, no auth
 * Usage: node relay/index.js
 */

import { WebSocketServer } from 'ws';

const PORT = 7777;
const events = new Map();          // eventId -> event
const subscriptions = new Map();   // ws -> Map(subId -> filters[])

const wss = new WebSocketServer({ port: PORT });

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

function handleEvent(sender, event) {
  if (!event || !event.id) {
    sender.send(JSON.stringify(['NOTICE', 'invalid event']));
    return;
  }

  const isNew = !events.has(event.id);
  events.set(event.id, event);

  sender.send(JSON.stringify(['OK', event.id, true, '']));

  if (!isNew) return;

  // Broadcast to all clients with matching subscriptions
  for (const [ws, subs] of subscriptions) {
    for (const [subId, filters] of subs) {
      if (matchesAny(event, filters)) {
        ws.send(JSON.stringify(['EVENT', subId, event]));
      }
    }
  }
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

  // Sort by created_at descending, apply smallest limit from filters
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

// --- Filter matching (NIP-01) ---

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

console.log(`Nostr relay listening on ws://localhost:${PORT}`);
