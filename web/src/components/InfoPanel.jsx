/**
 * InfoPanel - Right side info panel component
 */

import { isWasmReady, getWasm } from '../lib/wasm.js';
import * as store from './store.js';

export function InfoPanel({ identity, starkIdentity, wasmLoaded, qsslIdentity, slhDsaIdentity }) {
  const relays = store.connectedRelays.value;
  const transport = store.transportSecurity.value;
  const qsslStatus = store.getQsslStatus();

  // Fingerprint - prefer QSSL, fallback to STARK, then Nostr
  const fingerprint = qsslIdentity?.fingerprint || identity?.fingerprint || '-';

  // Nostr DM key - this is what users should share for encrypted DMs
  const nostrDmKey = store.getNostrPublicKey();
  const dmKeyShort = nostrDmKey ? nostrDmKey.slice(0, 16) : '-';

  // Encryption type - Full PQC stack
  let encryption = 'ML-KEM-1024 + AES-GCM';

  // Signature type - SLH-DSA (FIPS 205) + schnorr (relay compat)
  const signatureType = slhDsaIdentity ? 'SLH-DSA + SCHNORR' : 'SCHNORR ONLY';

  // QSSL status
  const qsslReady = qsslIdentity ? 'READY' : 'UNAVAIL';

  // QRNG
  let qrng = 'CSPRNG';
  if (wasmLoaded) {
    try {
      const wasm = getWasm();
      const available = wasm?.is_qrng_available?.();
      qrng = available ? 'QRNG ACTIVE' : 'CSPRNG (WASM)';
    } catch { /* fallback */ }
  }

  return (
    <aside class="lcars-info">
      <div class="lcars-bar lcars-info-header">INFO</div>
      <div class="lcars-info-content">
        <div class="lcars-info-item">
          <span class="lcars-label">IDENTITY</span>
          <span class="lcars-value">{fingerprint}</span>
        </div>
        <div class="lcars-info-item" title="Share this key for DMs" style="cursor: pointer;" onClick={() => {
          if (nostrDmKey) {
            navigator.clipboard.writeText(nostrDmKey);
            alert('DM Key copied to clipboard!');
          }
        }}>
          <span class="lcars-label">DM KEY 📋</span>
          <span class="lcars-value">{dmKeyShort}</span>
        </div>
        <div class="lcars-info-item">
          <span class="lcars-label">ENCRYPTION</span>
          <span class="lcars-value">{encryption}</span>
        </div>
        <div class="lcars-info-item">
          <span class="lcars-label">SIGNATURES</span>
          <span class="lcars-value">{signatureType}</span>
        </div>
        <div class="lcars-info-item">
          <span class="lcars-label">QRNG</span>
          <span class="lcars-value">{qrng}</span>
        </div>
        <div class="lcars-info-item">
          <span class="lcars-label">TRANSPORT</span>
          <span class="lcars-value">{transport}</span>
        </div>
        <div class="lcars-info-item" title={qsslIdentity ? `QSSL fingerprint: ${qsslIdentity.fingerprint}` : 'QSSL identity not initialized'}>
          <span class="lcars-label">QSSL</span>
          <span class="lcars-value">{qsslStatus.available ? `${qsslStatus.count} PQ` : qsslReady}</span>
        </div>
        <div class="lcars-info-item">
          <span class="lcars-label">NODE</span>
          <span class="lcars-value">{relays.length} RELAYS</span>
        </div>
        <div class="lcars-info-item">
          <span class="lcars-label">BLOCK</span>
          <span class="lcars-value">#0</span>
        </div>
      </div>
    </aside>
  );
}
