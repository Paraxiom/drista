/**
 * WASM Module Loader for Drista
 *
 * Loads qcomm-core compiled to WebAssembly, providing:
 * - STARK proofs (post-quantum event authentication)
 * - AES-256-GCM encryption/decryption
 * - QRNG / CSPRNG entropy
 */

let wasmModule = null;
let wasmReady = false;
let initPromise = null;

/**
 * Initialize the WASM module
 * @returns {Promise<object>} The initialized WASM module
 */
export async function initWasm() {
  if (wasmReady) return wasmModule;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const wasm = await import('../../pkg/qcomm_wasm.js');
      await wasm.default();

      wasmModule = wasm;
      wasmReady = true;

      console.log('[WASM] Module loaded, version:', wasm.version());
      console.log('[WASM] QRNG available:', wasm.is_qrng_available());

      return wasm;
    } catch (error) {
      console.error('[WASM] Failed to load:', error);
      initPromise = null;
      throw error;
    }
  })();

  return initPromise;
}

/**
 * Check if WASM is loaded
 */
export function isWasmReady() {
  return wasmReady;
}

/**
 * Get the loaded WASM module
 */
export function getWasm() {
  return wasmModule;
}
