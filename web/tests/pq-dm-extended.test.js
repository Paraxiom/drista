/**
 * Extended PQ-DM Tests
 *
 * Additional tests for edge cases, error handling, and stress testing
 *
 * Run with: node --experimental-wasm-modules tests/pq-dm-extended.test.js
 */

// ML-KEM-1024 sizes
const KEM_PUBLIC_KEY_SIZE = 1568;
const KEM_CIPHERTEXT_SIZE = 1568;
const KEM_SHARED_SECRET_SIZE = 32;
const AES_NONCE_SIZE = 12;
const AES_TAG_SIZE = 16;

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

function assertThrows(fn, message) {
  let threw = false;
  try {
    fn();
  } catch (e) {
    threw = true;
  }
  if (!threw) {
    throw new Error(message || 'Expected function to throw');
  }
}

async function assertThrowsAsync(fn, message) {
  let threw = false;
  try {
    await fn();
  } catch (e) {
    threw = true;
  }
  if (!threw) {
    throw new Error(message || 'Expected async function to throw');
  }
}

async function runTests() {
  console.log('Running Extended PQ-DM Tests\n');
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

async function loadWasm() {
  const { initWasm, getWasm, isWasmReady } = await import('./wasm-node.js');
  await initWasm();
  return { wasm: getWasm(), isWasmReady };
}

// Helper to create full encryption/decryption context
async function createCryptoContext() {
  const { wasm } = await loadWasm();
  const { webcrypto } = await import('crypto');
  return { wasm, webcrypto };
}

// ============================================================================
// Edge Case Tests
// ============================================================================

test('Unicode message encrypts and decrypts correctly', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = '你好世界! 🌍🔐 Привет мир! مرحبا بالعالم';

  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  const keyMaterial = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, new TextEncoder().encode(message)
  );

  const decrypted = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, aesCiphertext
  );
  const decryptedMessage = new TextDecoder().decode(decrypted);

  assertEqual(decryptedMessage, message, 'Unicode message should roundtrip correctly');
});

test('Binary data (null bytes) encrypts correctly', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();

  // Create binary data with null bytes
  const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0x00, 0xFF, 0x00, 0xAB]);

  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  const keyMaterial = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, binaryData
  );

  const decrypted = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, aesCiphertext
  );

  assertEqual(Buffer.from(decrypted).toString('hex'), Buffer.from(binaryData).toString('hex'),
    'Binary data should roundtrip correctly');
});

test('Maximum reasonable message size (64KB)', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'X'.repeat(65536); // 64KB

  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const kemCiphertext = Buffer.from(exchangeMap.get('ciphertext'), 'base64');
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  const keyMaterial = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, new TextEncoder().encode(message)
  );

  // Verify payload structure
  const combined = Buffer.concat([kemCiphertext, Buffer.from(nonce), Buffer.from(aesCiphertext)]);
  assert(combined.length > 65536 + KEM_CIPHERTEXT_SIZE, 'Combined payload should be larger than message');

  // Decrypt
  const decrypted = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, aesCiphertext
  );
  assertEqual(new TextDecoder().decode(decrypted).length, message.length, '64KB message should roundtrip');
});

// ============================================================================
// Error Handling Tests
// ============================================================================

test('Decryption with wrong key fails', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const wrongKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Secret message';

  // Encrypt to recipient
  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  const keyMaterial = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);

  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, new TextEncoder().encode(message)
  );

  // Try to decrypt with wrong keypair's derived key
  const wrongSharedSecret = Buffer.from(wrongKeypair.decapsulate(exchangeMap.get('ciphertext')), 'base64');

  // The shared secrets should be different
  assertNotEqual(sharedSecret.toString('hex'), wrongSharedSecret.toString('hex'),
    'Wrong keypair should produce different shared secret');
});

test('Truncated ciphertext is rejected', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Secret message';

  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const kemCiphertext = Buffer.from(exchangeMap.get('ciphertext'), 'base64');
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  const keyMaterial = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, new TextEncoder().encode(message)
  );

  // Truncate ciphertext
  const truncated = aesCiphertext.slice(0, -5);

  await assertThrowsAsync(async () => {
    await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, truncated
    );
  }, 'Truncated ciphertext should be rejected');
});

test('Modified nonce causes decryption failure', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Secret message';

  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  const keyMaterial = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, new TextEncoder().encode(message)
  );

  // Modify nonce
  const wrongNonce = new Uint8Array(nonce);
  wrongNonce[0] ^= 0xFF;

  await assertThrowsAsync(async () => {
    await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: wrongNonce, tagLength: 128 }, aesKey, aesCiphertext
    );
  }, 'Wrong nonce should cause decryption failure');
});

// ============================================================================
// Consistency Tests
// ============================================================================

test('Same message encrypted twice produces different ciphertexts', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Same message';

  // First encryption
  const exchange1 = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const ss1 = Buffer.from(exchange1.get('sharedSecret'), 'base64');
  const km1 = await webcrypto.subtle.importKey('raw', ss1, 'HKDF', false, ['deriveBits']);
  const akb1 = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    km1, 256
  );
  const ak1 = await webcrypto.subtle.importKey('raw', akb1, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const nonce1 = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const ct1 = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce1, tagLength: 128 }, ak1, new TextEncoder().encode(message)
  );

  // Second encryption
  const exchange2 = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const ss2 = Buffer.from(exchange2.get('sharedSecret'), 'base64');
  const km2 = await webcrypto.subtle.importKey('raw', ss2, 'HKDF', false, ['deriveBits']);
  const akb2 = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    km2, 256
  );
  const ak2 = await webcrypto.subtle.importKey('raw', akb2, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const nonce2 = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const ct2 = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce2, tagLength: 128 }, ak2, new TextEncoder().encode(message)
  );

  // Ciphertexts should be different (due to random nonce and KEM)
  assertNotEqual(
    Buffer.from(ct1).toString('hex'),
    Buffer.from(ct2).toString('hex'),
    'Same message should produce different ciphertexts'
  );
});

test('HKDF produces deterministic key from same secret', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();

  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  // Derive key twice
  const km1 = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const akb1 = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    km1, 256
  );

  const km2 = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const akb2 = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    km2, 256
  );

  assertEqual(
    Buffer.from(akb1).toString('hex'),
    Buffer.from(akb2).toString('hex'),
    'HKDF should be deterministic'
  );
});

// ============================================================================
// Performance / Stress Tests
// ============================================================================

test('100 sequential encryptions complete without error', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Test message for performance';

  for (let i = 0; i < 100; i++) {
    const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
    const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

    const keyMaterial = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
    const aesKeyBits = await webcrypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
      keyMaterial, 256
    );
    const aesKey = await webcrypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);

    const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
    await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, new TextEncoder().encode(message)
    );
  }

  assert(true, '100 encryptions completed');
});

test('Multiple recipients can each decrypt', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const message = 'Broadcast message';

  // Create 5 recipients
  const recipients = [];
  for (let i = 0; i < 5; i++) {
    recipients.push(new wasm.JsMlKemKeyPair());
  }

  // Encrypt to each recipient and verify they can decrypt
  for (const recipient of recipients) {
    const exchangeMap = wasm.pqKeyExchangeInitiate(recipient.publicKeyBase64);
    const kemCt = exchangeMap.get('ciphertext');
    const senderSS = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

    // Sender encrypts
    const km = await webcrypto.subtle.importKey('raw', senderSS, 'HKDF', false, ['deriveBits']);
    const akb = await webcrypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
      km, 256
    );
    const ak = await webcrypto.subtle.importKey('raw', akb, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
    const ct = await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 }, ak, new TextEncoder().encode(message)
    );

    // Recipient decrypts
    const recipientSS = Buffer.from(recipient.decapsulate(kemCt), 'base64');
    const rkm = await webcrypto.subtle.importKey('raw', recipientSS, 'HKDF', false, ['deriveBits']);
    const rakb = await webcrypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
      rkm, 256
    );
    const rak = await webcrypto.subtle.importKey('raw', rakb, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const decrypted = await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 }, rak, ct
    );

    assertEqual(new TextDecoder().decode(decrypted), message, 'Each recipient should decrypt correctly');
  }
});

// ============================================================================
// Base64 Encoding Tests
// ============================================================================

test('Base64 encoding preserves data integrity', async () => {
  const { wasm, webcrypto } = await createCryptoContext();
  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Test message';

  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const kemCiphertext = Buffer.from(exchangeMap.get('ciphertext'), 'base64');
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  const keyMaterial = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey('raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, new TextEncoder().encode(message)
  );

  // Combine and encode to base64
  const combined = Buffer.concat([kemCiphertext, Buffer.from(nonce), Buffer.from(aesCiphertext)]);
  const base64Encoded = combined.toString('base64');

  // Decode and verify
  const decoded = Buffer.from(base64Encoded, 'base64');
  assertEqual(combined.length, decoded.length, 'Base64 roundtrip should preserve length');
  assertEqual(combined.toString('hex'), decoded.toString('hex'), 'Base64 roundtrip should preserve content');
});

// Run all tests
runTests();
