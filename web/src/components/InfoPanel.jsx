/**
 * InfoPanel - Right side info panel component
 */

import { isWasmReady, getWasm } from '../lib/wasm.js';
import * as store from './store.js';

export function InfoPanel({ identity, starkIdentity, wasmLoaded, qsslIdentity }) {
  const relays = store.connectedRelays.value;
  const transport = store.transportSecurity.value;

  // Fingerprint - prefer QSSL, fallback to STARK, then Nostr
  const fingerprint = qsslIdentity?.fingerprint || identity?.fingerprint || '-';

  // Encryption type - QSSL uses ML-KEM-768 for post-quantum key exchange
  let encryption = 'NIP-04 / SECP256K1';
  if (qsslIdentity) {
    encryption = 'ML-KEM-768 + Ed25519';  // FIPS 203 PQC KEM
  } else if (starkIdentity) {
    encryption = 'STARK / WINTERFELL';
  }

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
        <div class="lcars-info-item">
          <span class="lcars-label">ENCRYPTION</span>
          <span class="lcars-value">{encryption}</span>
        </div>
        <div class="lcars-info-item">
          <span class="lcars-label">QRNG</span>
          <span class="lcars-value">{qrng}</span>
        </div>
        <div class="lcars-info-item">
          <span class="lcars-label">TRANSPORT</span>
          <span class="lcars-value">{transport}</span>
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
