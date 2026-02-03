/**
 * Test suite for PQ Crypto JavaScript module
 *
 * Run with: node --experimental-wasm-modules tests/pq-crypto.test.js
 * (from the web/ directory)
 */

// Simple test framework
let passed = 0;
let failed = 0;
const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${expected}, got ${actual}`);
  }
}

function assertNotEqual(actual, expected, message) {
  if (actual === expected) {
    throw new Error(message || `Expected values to differ, both were ${actual}`);
  }
}

async function runTests() {
  console.log('Running PQ Crypto JavaScript Tests\n');
  console.log('='.repeat(50));

  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`  PASS: ${name}`);
      passed++;
    } catch (error) {
      console.log(`  FAIL: ${name}`);
      console.log(`        ${error.message}`);
      failed++;
    }
  }

  console.log('='.repeat(50));
  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

// ============================================================================
// Import the module (dynamic import for ES modules)
// ============================================================================

// Use the nodejs-compatible WASM loader for tests
async function loadModules() {
  const { initWasm, getWasm, isWasmReady } = await import('./wasm-node.js');

  return { initWasm, getWasm, isWasmReady };
}

// ============================================================================
// Test Definitions
// ============================================================================

test('WASM module loads successfully', async () => {
  const { initWasm, isWasmReady } = await loadModules();
  await initWasm();
  assert(isWasmReady(), 'WASM should be ready after init');
});

test('Can generate ML-KEM keypair', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const kp = new wasm.JsMlKemKeyPair();
  const pk = kp.publicKeyBase64;

  assert(pk.length > 2000, 'Public key should be properly encoded base64');
});

test('ML-KEM keypairs are unique', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const kp1 = new wasm.JsMlKemKeyPair();
  const kp2 = new wasm.JsMlKemKeyPair();

  assertNotEqual(kp1.publicKeyBase64, kp2.publicKeyBase64, 'Keypairs should be unique');
});

test('Can encapsulate to public key', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const kp = new wasm.JsMlKemKeyPair();
  const result = kp.encapsulate();

  // serde_wasm_bindgen returns a Map
  const ciphertext = result.get('ciphertext');
  const sharedSecret = result.get('sharedSecret');

  assert(ciphertext, 'Should have ciphertext');
  assert(sharedSecret, 'Should have sharedSecret');
  assert(ciphertext.length > 2000, 'Ciphertext should be properly encoded');
});

test('Can decapsulate ciphertext', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const kp = new wasm.JsMlKemKeyPair();
  const result = kp.encapsulate();
  const ciphertext = result.get('ciphertext');
  const sharedSecret = result.get('sharedSecret');

  const decapsulated = kp.decapsulate(ciphertext);

  assertEqual(decapsulated, sharedSecret, 'Decapsulated secret should match');
});

test('pqKeyExchangeInitiate works', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const bobKp = new wasm.JsMlKemKeyPair();
  const bobPk = bobKp.publicKeyBase64;

  const result = wasm.pqKeyExchangeInitiate(bobPk);

  // serde_wasm_bindgen returns a Map
  assert(result.get('ciphertext'), 'Should have ciphertext');
  assert(result.get('sharedSecret'), 'Should have sharedSecret');
  assert(result.get('theirPublicKey'), 'Should have theirPublicKey');
});

test('STARK identity generation works', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const identity = new wasm.JsStarkIdentity();
  const pubkey = identity.pubkeyHex;

  assertEqual(pubkey.length, 64, 'Pubkey should be 64 hex chars (32 bytes)');
});

test('STARK identity from secret is deterministic', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  const id1 = wasm.JsStarkIdentity.fromSecret(secret);
  const id2 = wasm.JsStarkIdentity.fromSecret(secret);

  assertEqual(id1.pubkeyHex, id2.pubkeyHex, 'Same secret should give same pubkey');
});

test('AEAD encryption/decryption works', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const key = wasm.get_random_bytes(32);
  const plaintext = new TextEncoder().encode('Hello, WASM!');

  const ciphertext = wasm.encrypt_message(plaintext, key);
  const decrypted = wasm.decrypt_message(ciphertext, key);

  assertEqual(
    new TextDecoder().decode(new Uint8Array(decrypted)),
    'Hello, WASM!',
    'Decrypted should match plaintext'
  );
});

test('AEAD decryption with wrong key fails', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const key1 = wasm.get_random_bytes(32);
  const key2 = wasm.get_random_bytes(32);
  const plaintext = new TextEncoder().encode('Secret');

  const ciphertext = wasm.encrypt_message(plaintext, key1);

  let threw = false;
  try {
    wasm.decrypt_message(ciphertext, key2);
  } catch {
    threw = true;
  }

  assert(threw, 'Decryption with wrong key should throw');
});

test('Random bytes are unique', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const bytes1 = Array.from(wasm.get_random_bytes(32));
  const bytes2 = Array.from(wasm.get_random_bytes(32));

  const same = bytes1.every((b, i) => b === bytes2[i]);
  assert(!same, 'Random bytes should be unique');
});

test('Version is returned', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const ver = wasm.version();
  assert(ver.length > 0, 'Version should not be empty');
});

// ============================================================================
// PQ Session Tests (Triple Ratchet)
// ============================================================================

test('JsPqSession can be created as initiator', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  // Generate Bob's keypair
  const bobKp = new wasm.JsMlKemKeyPair();
  const bobPk = bobKp.publicKeyBase64;

  // Alice initiates key exchange
  const exchange = wasm.pqKeyExchangeInitiate(bobPk);

  // Create session as initiator (Map.get for serde_wasm_bindgen)
  const session = wasm.JsPqSession.initAsInitiator(
    exchange.get('sharedSecret'),
    exchange.get('theirPublicKey')
  );

  assert(session, 'Session should be created');
});

test('JsPqSession can encrypt messages', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  // Set up session
  const bobKp = new wasm.JsMlKemKeyPair();
  const exchange = wasm.pqKeyExchangeInitiate(bobKp.publicKeyBase64);
  const session = wasm.JsPqSession.initAsInitiator(
    exchange.get('sharedSecret'),
    exchange.get('theirPublicKey')
  );

  // Encrypt a message
  const plaintext = new TextEncoder().encode('Hello, post-quantum world!');
  const encrypted = session.encrypt(plaintext);

  // serde_wasm_bindgen returns a Map
  const header = encrypted.get('header');
  const ciphertext = encrypted.get('ciphertext');

  assert(header, 'Should have header');
  assert(ciphertext, 'Should have ciphertext');
  assert(header.length > 0, 'Header should not be empty');
  assert(ciphertext.length > 0, 'Ciphertext should not be empty');
});

test('Multiple encrypted messages have unique ciphertexts', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const bobKp = new wasm.JsMlKemKeyPair();
  const exchange = wasm.pqKeyExchangeInitiate(bobKp.publicKeyBase64);
  const session = wasm.JsPqSession.initAsInitiator(
    exchange.get('sharedSecret'),
    exchange.get('theirPublicKey')
  );

  const plaintext = new TextEncoder().encode('Same message');
  const encrypted1 = session.encrypt(plaintext);
  const encrypted2 = session.encrypt(plaintext);

  assertNotEqual(encrypted1.get('ciphertext'), encrypted2.get('ciphertext'), 'Each encryption should be unique');
});

test('Session message counters increment', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const bobKp = new wasm.JsMlKemKeyPair();
  const exchange = wasm.pqKeyExchangeInitiate(bobKp.publicKeyBase64);
  const session = wasm.JsPqSession.initAsInitiator(
    exchange.get('sharedSecret'),
    exchange.get('theirPublicKey')
  );

  // Encrypt multiple messages
  const msg1 = session.encrypt(new TextEncoder().encode('Message 1'));
  const msg2 = session.encrypt(new TextEncoder().encode('Message 2'));
  const msg3 = session.encrypt(new TextEncoder().encode('Message 3'));

  // Headers should be different (different message numbers)
  assert(msg1.get('header') !== msg2.get('header'), 'Headers should differ');
  assert(msg2.get('header') !== msg3.get('header'), 'Headers should differ');
});

// ============================================================================
// Full Key Exchange Simulation
// ============================================================================

test('Full key exchange: Alice initiates to Bob', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  // Bob generates his KEM keypair
  const bobKp = new wasm.JsMlKemKeyPair();
  const bobPublicKey = bobKp.publicKeyBase64;

  // Alice initiates key exchange with Bob's public key
  const aliceExchange = wasm.pqKeyExchangeInitiate(bobPublicKey);

  // Verify Alice got all the pieces (Map.get for serde_wasm_bindgen)
  assert(aliceExchange.get('ciphertext'), 'Alice should have ciphertext to send to Bob');
  assert(aliceExchange.get('sharedSecret'), 'Alice should have shared secret');
  assert(aliceExchange.get('theirPublicKey'), 'Alice should have Bob\'s public key');

  // Bob decapsulates to get the same shared secret
  const bobSharedSecret = bobKp.decapsulate(aliceExchange.get('ciphertext'));

  // Both should have the same shared secret
  assertEqual(
    aliceExchange.get('sharedSecret'),
    bobSharedSecret,
    'Alice and Bob should derive the same shared secret'
  );
});

test('Key exchange produces unique secrets each time', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const bobKp = new wasm.JsMlKemKeyPair();
  const bobPublicKey = bobKp.publicKeyBase64;

  // Two different key exchanges
  const exchange1 = wasm.pqKeyExchangeInitiate(bobPublicKey);
  const exchange2 = wasm.pqKeyExchangeInitiate(bobPublicKey);

  assertNotEqual(
    exchange1.get('sharedSecret'),
    exchange2.get('sharedSecret'),
    'Different key exchanges should produce different secrets'
  );
  assertNotEqual(
    exchange1.get('ciphertext'),
    exchange2.get('ciphertext'),
    'Different key exchanges should produce different ciphertexts'
  );
});

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

test('AEAD handles empty message', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const key = wasm.get_random_bytes(32);
  const plaintext = new Uint8Array(0);

  const ciphertext = wasm.encrypt_message(plaintext, key);
  const decrypted = wasm.decrypt_message(ciphertext, key);

  assertEqual(decrypted.length, 0, 'Decrypted empty message should be empty');
});

test('AEAD handles large message', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const key = wasm.get_random_bytes(32);
  // 1MB message
  const plaintext = wasm.get_random_bytes(1024 * 1024);

  const ciphertext = wasm.encrypt_message(plaintext, key);
  const decrypted = wasm.decrypt_message(ciphertext, key);

  assertEqual(decrypted.length, plaintext.length, 'Decrypted should match original size');

  // Verify content matches
  let matches = true;
  for (let i = 0; i < plaintext.length && matches; i++) {
    if (plaintext[i] !== decrypted[i]) matches = false;
  }
  assert(matches, 'Decrypted content should match original');
});

test('Tampered ciphertext is rejected', async () => {
  const { initWasm, getWasm } = await loadModules();
  await initWasm();
  const wasm = getWasm();

  const key = wasm.get_random_bytes(32);
  const plaintext = new TextEncoder().encode('Important message');

  const ciphertext = wasm.encrypt_message(plaintext, key);

  // Tamper with the ciphertext
  const tampered = new Uint8Array(ciphertext);
  tampered[tampered.length - 1] ^= 0xFF;

  let threw = false;
  try {
    wasm.decrypt_message(tampered, key);
  } catch {
    threw = true;
  }

  assert(threw, 'Tampered ciphertext should be rejected');
});

// NOTE: PQ Crypto Manager tests (initPqCrypto, getPublicKey, hasSession) require
// browser environment due to fetch-based WASM loading. Test those in browser or
// with a proper test framework like Playwright.

// ============================================================================
// Run all tests
// ============================================================================

runTests().catch(error => {
  console.error('Test runner error:', error);
  process.exit(1);
});
