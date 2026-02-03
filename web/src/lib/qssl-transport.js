/**
 * QSSL Transport Layer for Drista
 *
 * Provides post-quantum encrypted WebSocket connections using:
 * - ML-KEM-768 (FIPS 203) for key encapsulation
 * - ML-DSA-65 (FIPS 204) for digital signatures
 * - AES-256-GCM for symmetric encryption
 *
 * This wraps the QSSL WASM module (qssl-wasm) for browser use.
 */

let qsslModule = null;
let qsslIdentity = null;

// QSSL connection state
const QSSL_STATE = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  HANDSHAKING: 'handshaking',
  CONNECTED: 'connected',
  ERROR: 'error',
};

/**
 * Initialize the QSSL WASM module
 * Note: QSSL WASM is optional and may not be available
 */
export async function initQssl() {
  if (qsslModule) return qsslModule;

  try {
    // Dynamic import path constructed at runtime to avoid Vite bundling issues
    // when the module doesn't exist
    const wasmPath = '../qssl/qssl_wasm.js';
    const wasm = await import(/* @vite-ignore */ wasmPath);
    await wasm.default();
    qsslModule = wasm;
    console.log('[QSSL] WASM module initialized, version:', wasm.version());
    return qsslModule;
  } catch (error) {
    console.warn('[QSSL] WASM module not available (optional):', error.message);
    return null;
  }
}

/**
 * Get or create QSSL identity
 */
export function getQsslIdentity() {
  if (qsslIdentity) return qsslIdentity;

  // Try to load from localStorage
  const stored = localStorage.getItem('drista_qssl_identity');
  if (stored) {
    try {
      const bytes = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
      qsslIdentity = qsslModule.QsslIdentity.import(bytes);
      console.log('[QSSL] Loaded identity, fingerprint:', qsslIdentity.fingerprint);
      return qsslIdentity;
    } catch (error) {
      console.warn('[QSSL] Failed to load stored identity:', error);
    }
  }

  // Generate new identity
  qsslIdentity = qsslModule.generate_identity();
  console.log('[QSSL] Generated new identity, fingerprint:', qsslIdentity.fingerprint);

  // Store it
  const exported = qsslIdentity.export();
  localStorage.setItem('drista_qssl_identity', btoa(String.fromCharCode(...exported)));

  return qsslIdentity;
}

/**
 * QSSL-secured relay connection
 */
export class QsslRelayConnection {
  constructor(url) {
    this.url = url;
    this.connection = null;
    this.state = QSSL_STATE.DISCONNECTED;
    this.listeners = {
      message: [],
      connect: [],
      disconnect: [],
      error: [],
    };
    this.pendingMessages = [];
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

  async connect() {
    if (!qsslModule) {
      await initQssl();
    }

    const identity = getQsslIdentity();
    this.state = QSSL_STATE.CONNECTING;

    return new Promise((resolve, reject) => {
      try {
        // Convert /ws endpoint to /qssl endpoint for QSSL transport
        // e.g., wss://drista.paraxiom.org/ws -> wss://drista.paraxiom.org/qssl
        const qsslUrl = this.url.replace(/\/ws$/, '/qssl');

        this.connection = new qsslModule.QsslConnection(qsslUrl, identity);

        this.connection.set_on_connect(() => {
          console.log('[QSSL] Connected to', this.url);
          this.state = QSSL_STATE.CONNECTED;

          // Send pending messages
          while (this.pendingMessages.length > 0) {
            const msg = this.pendingMessages.shift();
            this.send(msg);
          }

          this.emit('connect', { url: this.url });
          resolve();
        });

        this.connection.set_on_message((data) => {
          try {
            const text = new TextDecoder().decode(data);
            const message = JSON.parse(text);
            this.handleMessage(message);
          } catch (error) {
            console.error('[QSSL] Failed to parse message:', error);
          }
        });

      } catch (error) {
        this.state = QSSL_STATE.ERROR;
        this.emit('error', { url: this.url, error });
        reject(error);
      }
    });
  }

  handleMessage(message) {
    const [type, ...rest] = message;

    switch (type) {
      case 'EVENT': {
        const [subId, event] = rest;
        this.emit('message', { subId, event, relay: this.url, qsslSecured: true });
        break;
      }
      case 'OK': {
        const [eventId, success, msg] = rest;
        console.log(`[QSSL] OK: ${eventId} - ${success}`);
        break;
      }
      case 'EOSE': {
        console.log(`[QSSL] End of stored events for ${rest[0]}`);
        break;
      }
      case 'NOTICE': {
        console.log(`[QSSL] Notice: ${rest[0]}`);
        break;
      }
    }
  }

  send(message) {
    if (this.state !== QSSL_STATE.CONNECTED || !this.connection) {
      this.pendingMessages.push(message);
      return;
    }

    const json = JSON.stringify(message);
    const bytes = new TextEncoder().encode(json);
    this.connection.send(bytes);
  }

  subscribe(filters, callback) {
    const subId = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
    this.send(['REQ', subId, ...filters]);
    return subId;
  }

  unsubscribe(subId) {
    this.send(['CLOSE', subId]);
  }

  publish(event) {
    this.send(['EVENT', event]);
  }

  disconnect() {
    if (this.connection) {
      this.connection.close();
      this.connection = null;
    }
    this.state = QSSL_STATE.DISCONNECTED;
    this.emit('disconnect', { url: this.url });
  }

  get connected() {
    return this.state === QSSL_STATE.CONNECTED;
  }

  get fingerprint() {
    return qsslIdentity?.fingerprint || null;
  }
}

/**
 * Check if QSSL is available
 */
export function isQsslAvailable() {
  return qsslModule !== null;
}

/**
 * Get QSSL status
 */
export function getQsslStatus() {
  return {
    available: isQsslAvailable(),
    fingerprint: qsslIdentity?.fingerprint || null,
    version: qsslModule?.version() || null,
  };
}
