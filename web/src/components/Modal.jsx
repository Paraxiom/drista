/**
 * Modal - Overlay + dialog components
 */

import { useState, useEffect, useRef } from 'preact/hooks';
import * as store from './store.js';

export function ModalOverlay({ identity, starkIdentity, wasmLoaded }) {
  const modal = store.activeModal.value;

  useEffect(() => {
    function onKey(e) {
      if (e.key === 'Escape') {
        store.activeModal.value = null;
      }
    }
    if (modal) {
      document.addEventListener('keydown', onKey);
      return () => document.removeEventListener('keydown', onKey);
    }
  }, [modal]);

  if (!modal) return null;

  function close() {
    store.activeModal.value = null;
  }

  return (
    <div class="modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) close(); }}>
      <div class="modal-content">
        {modal === 'newDM' && <NewDMDialog onClose={close} />}
        {modal === 'newGroup' && <NewGroupDialog onClose={close} />}
        {modal === 'settings' && <SettingsDialog onClose={close} identity={identity} starkIdentity={starkIdentity} wasmLoaded={wasmLoaded} />}
        {modal === 'relayInfo' && <RelayInfoDialog onClose={close} />}
      </div>
    </div>
  );
}

function NewDMDialog({ onClose }) {
  const [pubkey, setPubkey] = useState('');
  const [error, setError] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  function submit() {
    const val = pubkey.trim();
    if (!val || val.length < 64) {
      setError('Invalid public key. Must be 64 hex characters.');
      return;
    }

    const channelId = `dm:${val}`;
    if (store.getChannel(channelId)) {
      store.setCurrentChannel(channelId);
      onClose();
      return;
    }

    store.addChannel({
      id: channelId,
      name: val.slice(0, 12) + '...',
      channelType: 'direct',
      encrypted: true,
      pqcEnabled: false,
      unreadCount: 0,
      nostrPubkey: val,
    });
    store.setCurrentChannel(channelId);
    onClose();
  }

  function onKeyDown(e) {
    if (e.key === 'Enter') submit();
  }

  return (
    <div class="modal-dialog">
      <div class="modal-title">NEW DIRECT MESSAGE</div>
      <input
        ref={inputRef}
        class="modal-input"
        type="text"
        placeholder="Enter recipient Nostr public key (hex)..."
        value={pubkey}
        onInput={(e) => { setPubkey(e.target.value); setError(''); }}
        onKeyDown={onKeyDown}
      />
      {error && <div class="modal-error">{error}</div>}
      <div class="modal-actions">
        <button class="lcars-button" onClick={onClose}>CANCEL</button>
        <button class="lcars-button lcars-primary" onClick={submit}>CONNECT</button>
      </div>
    </div>
  );
}

function NewGroupDialog({ onClose }) {
  const [name, setName] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  function submit() {
    const val = name.trim();
    if (!val) return;

    const channelId = `#${val.toLowerCase().replace(/[^a-z0-9]/g, '')}`;

    store.addChannel({
      id: channelId,
      name: `#${val}`,
      channelType: 'forum',
      encrypted: false,
      pqcEnabled: false,
      unreadCount: 0,
    });
    store.setCurrentChannel(channelId);
    onClose();
  }

  function onKeyDown(e) {
    if (e.key === 'Enter') submit();
  }

  return (
    <div class="modal-dialog">
      <div class="modal-title">NEW GROUP CHANNEL</div>
      <input
        ref={inputRef}
        class="modal-input"
        type="text"
        placeholder="Enter channel name..."
        value={name}
        onInput={(e) => setName(e.target.value)}
        onKeyDown={onKeyDown}
      />
      <div class="modal-actions">
        <button class="lcars-button" onClick={onClose}>CANCEL</button>
        <button class="lcars-button lcars-primary" onClick={submit}>CREATE</button>
      </div>
    </div>
  );
}

function SettingsDialog({ onClose, identity, starkIdentity, wasmLoaded }) {
  const pubkey = identity?.publicKey || 'Not initialized';
  const idType = identity?.type === 'stark' ? 'STARK (Post-Quantum)' : 'Nostr (secp256k1)';
  const nostrPubkey = store.getNostrPublicKey() || 'N/A';

  return (
    <div class="modal-dialog">
      <div class="modal-title">SETTINGS — दृष्टि</div>
      <div class="modal-info-row">
        <span class="lcars-label">IDENTITY TYPE</span>
        <span class="lcars-value">{idType}</span>
      </div>
      <div class="modal-info-row">
        <span class="lcars-label">PUBLIC KEY</span>
        <span class="lcars-value" style="word-break:break-all">{pubkey}</span>
      </div>
      {starkIdentity && (
        <div class="modal-info-row">
          <span class="lcars-label">STARK FINGERPRINT</span>
          <span class="lcars-value">{starkIdentity.fingerprint}</span>
        </div>
      )}
      <div class="modal-info-row">
        <span class="lcars-label">NOSTR TRANSPORT KEY</span>
        <span class="lcars-value" style="word-break:break-all">{nostrPubkey}</span>
      </div>
      <div class="modal-info-row">
        <span class="lcars-label">WASM</span>
        <span class="lcars-value">{wasmLoaded ? 'Loaded' : 'Not available'}</span>
      </div>
      <div class="modal-actions">
        <button class="lcars-button lcars-primary" onClick={onClose}>CLOSE</button>
      </div>
    </div>
  );
}

function RelayInfoDialog({ onClose }) {
  const relays = store.connectedRelays.value;
  const status = store.nostrStatus.value;

  return (
    <div class="modal-dialog">
      <div class="modal-title">NOSTR RELAY STATUS</div>
      <div class="modal-info-row">
        <span class="lcars-label">STATUS</span>
        <span class="lcars-value">{status.toUpperCase()}</span>
      </div>
      <div class="modal-info-row">
        <span class="lcars-label">CONNECTED RELAYS ({relays.length})</span>
        <span class="lcars-value">
          {relays.length > 0
            ? relays.map(r => <div key={r}>• {r}</div>)
            : '• None connected'}
        </span>
      </div>
      <div class="modal-actions">
        <button class="lcars-button lcars-primary" onClick={onClose}>CLOSE</button>
      </div>
    </div>
  );
}
