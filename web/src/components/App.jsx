/**
 * Drista - Main Application Component (Preact)
 */

import { useEffect, useState } from 'preact/hooks';
import { initWasm, isWasmReady, getWasm } from '../lib/wasm.js';
import { StarkIdentityManager } from '../lib/stark-identity.js';
import { initQssl, getQsslIdentity, isQsslAvailable } from '../lib/qssl-transport.js';
import * as store from './store.js';
import { ChannelList } from './ChannelList.jsx';
import { ChatView } from './ChatView.jsx';
import { InfoPanel } from './InfoPanel.jsx';
import { ModalOverlay } from './Modal.jsx';

export function App() {
  const [identity, setIdentity] = useState(null);
  const [starkIdentity, setStarkIdentity] = useState(null);
  const [qsslIdentity, setQsslIdentity] = useState(null);
  const [wasmLoaded, setWasmLoaded] = useState(false);
  const [statusText, setStatusText] = useState('INITIALIZING');

  useEffect(() => {
    (async () => {
      // Step 1: Load WASM (PQ proofs)
      let wasm = false;
      try {
        setStatusText('LOADING WASM');
        await initWasm();
        wasm = true;
        setWasmLoaded(true);
        console.log('[Drista] WASM module loaded');
      } catch (error) {
        console.warn('[Drista] WASM unavailable, running without PQ proofs:', error);
      }

      // Step 2: QSSL identity (encrypted transport)
      let qssl = null;
      try {
        setStatusText('QSSL INIT');
        await initQssl();
        qssl = getQsslIdentity();
        setQsslIdentity({ fingerprint: qssl.fingerprint });
        console.log('[App] QSSL identity ready:', qssl.fingerprint);
      } catch (error) {
        console.warn('[App] QSSL unavailable:', error);
      }

      // Step 3: STARK identity (if WASM loaded)
      let id = null;
      let stark = null;
      if (wasm) {
        try {
          setStatusText('STARK INIT');
          stark = new StarkIdentityManager();

          const forceNew = new URLSearchParams(window.location.search).has('newid');
          if (forceNew) {
            localStorage.removeItem('drista_stark_secret');
            localStorage.removeItem('drista_stark_pubkey');
          }

          const { pubkeyHex } = stark.init();
          id = {
            publicKey: pubkeyHex,
            fingerprint: pubkeyHex.slice(0, 16),
            type: 'stark',
          };
          setStarkIdentity(stark);
          store.setStarkIdentity(stark);
          console.log('[App] STARK identity ready:', id.fingerprint + '...');
        } catch (error) {
          console.warn('[App] STARK identity failed, falling back to Nostr keys:', error);
          stark = null;
        }
      }

      // Step 4: Nostr init
      try {
        if (!id) {
          setStatusText('GENERATING KEYS');
          const keys = store.initNostr();
          id = {
            publicKey: keys.publicKey,
            fingerprint: keys.publicKey.slice(0, 16),
            type: 'nostr',
          };
        } else {
          setStatusText('NOSTR TRANSPORT');
          store.initNostr();
        }

        setIdentity(id);
        setStatusText('CONNECTING');
        await store.connectNostr();
        setStatusText('CONNECTED');
        console.log('[App] Initialized, identity type:', id.type, 'fingerprint:', id.fingerprint);
      } catch (error) {
        console.error('[App] Failed to initialize Nostr:', error);
        setStatusText('OFFLINE');
        if (id) setIdentity(id);
      }
    })();
  }, []);

  // Derive status color
  const statusColors = {
    'CONNECTED': 'var(--lcars-sage)',
    'CONNECTING': 'var(--lcars-peach)',
    'PARTIAL': 'var(--lcars-lavender)',
    'OFFLINE': 'var(--lcars-rose)',
    'INITIALIZING': 'var(--lcars-champagne)',
    'GENERATING KEYS': 'var(--lcars-mauve)',
    'LOADING WASM': 'var(--lcars-lavender)',
    'QSSL INIT': 'var(--lcars-sage)',
    'STARK INIT': 'var(--lcars-mauve)',
    'NOSTR TRANSPORT': 'var(--lcars-peach)',
    'ERROR': 'var(--lcars-rose)',
  };

  // Sync nostrStatus signal → statusText
  const ns = store.nostrStatus.value;
  const statusMap = {
    connected: 'CONNECTED',
    partial: 'PARTIAL',
    connecting: 'CONNECTING',
    disconnected: 'OFFLINE',
  };
  const derivedStatus = (statusText === 'CONNECTED' || statusText === 'PARTIAL' || statusText === 'OFFLINE' || statusText === 'CONNECTING')
    ? (statusMap[ns] || 'OFFLINE')
    : statusText;

  // Version from WASM
  let version = 'v0.1.0';
  if (wasmLoaded) {
    try {
      const w = getWasm();
      const ver = w?.version?.();
      if (ver) version = `v${ver}`;
    } catch { /* fallback */ }
  }

  return (
    <div class="lcars-frame">
      {/* Header */}
      <header class="lcars-header">
        <div class="lcars-elbow lcars-elbow-tl"></div>
        <div class="lcars-bar lcars-header-bar">
          <span class="lcars-title">DRISTA — The Observer — PQC DECENTRALIZED CHAT — दृष्टि</span>
        </div>
        <div class="lcars-button-group">
          <button class="lcars-button" onClick={() => { store.activeModal.value = 'settings'; }}>SETTINGS</button>
          <button class="lcars-button" onClick={() => { store.activeModal.value = 'relayInfo'; }}>NODE</button>
        </div>
      </header>

      {/* Main content */}
      <main class="lcars-main">
        <ChannelList />
        <ChatView identity={identity} starkIdentity={starkIdentity} wasmLoaded={wasmLoaded} />
        <InfoPanel identity={identity} starkIdentity={starkIdentity} wasmLoaded={wasmLoaded} qsslIdentity={qsslIdentity} />
      </main>

      {/* Footer */}
      <footer class="lcars-footer">
        <div class="lcars-elbow lcars-elbow-bl"></div>
        <div class="lcars-bar lcars-footer-bar">
          <span class="lcars-version">{version}</span>
          <span class="lcars-copyright">QUANTUM HARMONY</span>
        </div>
      </footer>

      {/* Modals */}
      <ModalOverlay identity={identity} starkIdentity={starkIdentity} wasmLoaded={wasmLoaded} />
    </div>
  );
}
