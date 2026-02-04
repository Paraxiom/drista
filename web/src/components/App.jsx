/**
 * Drista - Main Application Component (Preact)
 */

import { useEffect, useState, useCallback } from 'preact/hooks';
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
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Close mobile menu when channel is selected
  const handleChannelSelect = useCallback(() => {
    setMobileMenuOpen(false);
  }, []);

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

        // Step 4: Initialize PQ-DM (post-quantum encryption)
        if (wasm) {
          try {
            setStatusText('PQ-DM INIT');
            await store.initPqDm();
            // Publish our PQ encapsulation key for discovery
            await store.publishPqKey();
            console.log('[App] PQ-DM initialized and key published');
          } catch (error) {
            console.warn('[App] PQ-DM init failed, falling back to NIP-04:', error);
          }
        }

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
    'PQ-DM INIT': 'linear-gradient(135deg, #7ecfdf 0%, #5ab8c8 100%)',
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
        <div class="lcars-elbow lcars-elbow-tl">
          <span class="lcars-sanskrit">दृष्टि</span>
        </div>
        <button
          class="mobile-menu-btn"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          style="display: none;"
        >
          ☰
        </button>
        <div class="lcars-bar lcars-header-bar">
          <span class="lcars-title">DRISTA — The Observer — PQC DECENTRALIZED CHAT</span>
        </div>
        <div class="lcars-button-group">
          <button class="lcars-button" onClick={() => { store.activeModal.value = 'settings'; }}>SETTINGS</button>
          <button class="lcars-button" onClick={() => { store.activeModal.value = 'relayInfo'; }}>NODE</button>
          <img src="/assets/paraxiom_logo.png" alt="Paraxiom" class="lcars-logo" />
        </div>
      </header>

      {/* Mobile menu overlay */}
      {mobileMenuOpen && (
        <div class="mobile-overlay" onClick={() => setMobileMenuOpen(false)} />
      )}

      {/* Main content */}
      <main class="lcars-main">
        <ChannelList mobileOpen={mobileMenuOpen} onChannelSelect={handleChannelSelect} />
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
