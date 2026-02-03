/**
 * Node.js WASM Loader for testing
 *
 * Uses the nodejs-target WASM build for Node.js compatibility.
 */

let wasmModule = null;
let wasmReady = false;

/**
 * Initialize the WASM module for Node.js
 */
export async function initWasm() {
  if (wasmReady) return wasmModule;

  try {
    // Use the nodejs-target build
    const wasm = await import('../pkg-node/qcomm_wasm.js');

    wasmModule = wasm;
    wasmReady = true;

    console.log('[WASM] Module loaded, version:', wasm.version());

    return wasm;
  } catch (error) {
    console.error('[WASM] Failed to load:', error);
    throw error;
  }
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
