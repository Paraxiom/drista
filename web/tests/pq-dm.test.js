/**
 * PQ-DM Module Tests
 *
 * Tests the post-quantum DM encryption using ML-KEM-1024 + AES-256-GCM
 *
 * Run with: node --experimental-wasm-modules tests/pq-dm.test.js
 * (from the web/ directory)
 */

// ML-KEM-1024 sizes
const KEM_PUBLIC_KEY_SIZE = 1568;
const KEM_CIPHERTEXT_SIZE = 1568;
const KEM_SHARED_SECRET_SIZE = 32;
const AES_NONCE_SIZE = 12;

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
  console.log('Running PQ-DM Tests (ML-KEM-1024 + AES-256-GCM)\n');
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

// Use the nodejs-compatible WASM loader
async function loadWasm() {
  const { initWasm, getWasm, isWasmReady } = await import('./wasm-node.js');
  await initWasm();
  return { wasm: getWasm(), isWasmReady };
}

// ============================================================================
// Test Definitions
// ============================================================================

test('ML-KEM-1024 encapsulation key is 1568 bytes', async () => {
  const { wasm } = await loadWasm();
  const keypair = new wasm.JsMlKemKeyPair();
  const ekBase64 = keypair.publicKeyBase64;
  const ekBytes = Buffer.from(ekBase64, 'base64');
  assertEqual(ekBytes.length, KEM_PUBLIC_KEY_SIZE, `EK should be ${KEM_PUBLIC_KEY_SIZE} bytes, got ${ekBytes.length}`);
});

test('ML-KEM-1024 ciphertext is 1568 bytes', async () => {
  const { wasm } = await loadWasm();
  const keypair = new wasm.JsMlKemKeyPair();
  const exchangeMap = wasm.pqKeyExchangeInitiate(keypair.publicKeyBase64);
  const ctBytes = Buffer.from(exchangeMap.get('ciphertext'), 'base64');
  assertEqual(ctBytes.length, KEM_CIPHERTEXT_SIZE, `Ciphertext should be ${KEM_CIPHERTEXT_SIZE} bytes, got ${ctBytes.length}`);
});

test('ML-KEM-1024 shared secret is 32 bytes', async () => {
  const { wasm } = await loadWasm();
  const keypair = new wasm.JsMlKemKeyPair();
  const exchangeMap = wasm.pqKeyExchangeInitiate(keypair.publicKeyBase64);
  const ssBytes = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');
  assertEqual(ssBytes.length, KEM_SHARED_SECRET_SIZE, `Shared secret should be ${KEM_SHARED_SECRET_SIZE} bytes, got ${ssBytes.length}`);
});

test('Encapsulation and decapsulation produce same shared secret', async () => {
  const { wasm } = await loadWasm();
  const keypair = new wasm.JsMlKemKeyPair();
  const exchangeMap = wasm.pqKeyExchangeInitiate(keypair.publicKeyBase64);
  const encapsulatedSS = exchangeMap.get('sharedSecret');
  const decapsulatedSS = keypair.decapsulate(exchangeMap.get('ciphertext'));
  assertEqual(encapsulatedSS, decapsulatedSS,
    'Encapsulated and decapsulated shared secrets should match');
});

test('PQ-DM encryption format: KEM_CT(1568) + nonce(12) + AES_CT', async () => {
  const { wasm } = await loadWasm();
  const { webcrypto } = await import('crypto');

  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Hello, post-quantum world!';

  // Simulate encryption (what pq-dm.js encryptPqDm does)
  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const kemCiphertext = Buffer.from(exchangeMap.get('ciphertext'), 'base64');
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  // Derive AES key using HKDF
  const keyMaterial = await webcrypto.subtle.importKey(
    'raw', sharedSecret, 'HKDF', false, ['deriveBits']
  );
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey(
    'raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );

  // Encrypt
  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const plaintext = new TextEncoder().encode(message);
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, plaintext
  );

  // Combine: KEM_CT (1568) + nonce (12) + AES_CT
  const combined = Buffer.concat([
    kemCiphertext,
    Buffer.from(nonce),
    Buffer.from(aesCiphertext)
  ]);

  // Verify format
  const expectedMinSize = KEM_CIPHERTEXT_SIZE + AES_NONCE_SIZE;
  assert(combined.length > expectedMinSize, `Combined should be > ${expectedMinSize} bytes`);
  assertEqual(combined.slice(0, KEM_CIPHERTEXT_SIZE).length, KEM_CIPHERTEXT_SIZE, 'First 1568 bytes should be KEM ciphertext');
  assertEqual(combined.slice(KEM_CIPHERTEXT_SIZE, KEM_CIPHERTEXT_SIZE + AES_NONCE_SIZE).length, AES_NONCE_SIZE, 'Next 12 bytes should be nonce');
});

test('Full encrypt/decrypt roundtrip', async () => {
  const { wasm } = await loadWasm();
  const { webcrypto } = await import('crypto');

  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Post-quantum secure message!';

  // === ENCRYPT (sender side) ===
  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const kemCiphertext = Buffer.from(exchangeMap.get('ciphertext'), 'base64');
  const senderSharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  // Derive AES key
  const senderKeyMaterial = await webcrypto.subtle.importKey(
    'raw', senderSharedSecret, 'HKDF', false, ['deriveBits']
  );
  const senderAesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    senderKeyMaterial, 256
  );
  const senderAesKey = await webcrypto.subtle.importKey(
    'raw', senderAesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );

  // Encrypt message
  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const plaintext = new TextEncoder().encode(message);
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, senderAesKey, plaintext
  );

  // Create combined payload
  const combined = Buffer.concat([
    kemCiphertext,
    Buffer.from(nonce),
    Buffer.from(aesCiphertext)
  ]);
  const content = combined.toString('base64');

  // === DECRYPT (recipient side) ===
  const combinedDecrypt = Buffer.from(content, 'base64');

  // Parse
  const kemCt = combinedDecrypt.slice(0, KEM_CIPHERTEXT_SIZE);
  const nonceDecrypt = combinedDecrypt.slice(KEM_CIPHERTEXT_SIZE, KEM_CIPHERTEXT_SIZE + AES_NONCE_SIZE);
  const aesCtDecrypt = combinedDecrypt.slice(KEM_CIPHERTEXT_SIZE + AES_NONCE_SIZE);

  // Decapsulate
  const recipientSharedSecretBase64 = recipientKeypair.decapsulate(kemCt.toString('base64'));
  const recipientSharedSecret = Buffer.from(recipientSharedSecretBase64, 'base64');

  // Derive AES key
  const recipientKeyMaterial = await webcrypto.subtle.importKey(
    'raw', recipientSharedSecret, 'HKDF', false, ['deriveBits']
  );
  const recipientAesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    recipientKeyMaterial, 256
  );
  const recipientAesKey = await webcrypto.subtle.importKey(
    'raw', recipientAesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );

  // Decrypt
  const decrypted = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonceDecrypt, tagLength: 128 }, recipientAesKey, aesCtDecrypt
  );
  const decryptedMessage = new TextDecoder().decode(decrypted);

  assertEqual(decryptedMessage, message, 'Decrypted message should match original');
});

test('Tampering with ciphertext is detected', async () => {
  const { wasm } = await loadWasm();
  const { webcrypto } = await import('crypto');

  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'Secret message';

  // Encrypt
  const exchangeMap = wasm.pqKeyExchangeInitiate(recipientKeypair.publicKeyBase64);
  const kemCiphertext = Buffer.from(exchangeMap.get('ciphertext'), 'base64');
  const sharedSecret = Buffer.from(exchangeMap.get('sharedSecret'), 'base64');

  const keyMaterial = await webcrypto.subtle.importKey(
    'raw', sharedSecret, 'HKDF', false, ['deriveBits']
  );
  const aesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    keyMaterial, 256
  );
  const aesKey = await webcrypto.subtle.importKey(
    'raw', aesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );

  const nonce = webcrypto.getRandomValues(new Uint8Array(AES_NONCE_SIZE));
  const aesCiphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, new TextEncoder().encode(message)
  );

  const combined = Buffer.concat([kemCiphertext, Buffer.from(nonce), Buffer.from(aesCiphertext)]);

  // Tamper with AES ciphertext
  combined[combined.length - 10] ^= 0xFF;

  // Try to decrypt (should fail)
  const aesCtTampered = combined.slice(KEM_CIPHERTEXT_SIZE + AES_NONCE_SIZE);

  let tamperedDetected = false;
  try {
    await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, aesCtTampered
    );
  } catch (e) {
    tamperedDetected = true;
  }

  assert(tamperedDetected, 'AES-GCM should detect tampering');
});

test('Different encapsulations produce different ciphertexts', async () => {
  const { wasm } = await loadWasm();
  const keypair = new wasm.JsMlKemKeyPair();

  const exchange1 = wasm.pqKeyExchangeInitiate(keypair.publicKeyBase64);
  const exchange2 = wasm.pqKeyExchangeInitiate(keypair.publicKeyBase64);

  assertNotEqual(exchange1.get('ciphertext'), exchange2.get('ciphertext'),
    'Different encapsulations should produce different ciphertexts');
  assertNotEqual(exchange1.get('sharedSecret'), exchange2.get('sharedSecret'),
    'Different encapsulations should produce different shared secrets');
});

test('Multiple keypairs are unique', async () => {
  const { wasm } = await loadWasm();
  const keypair1 = new wasm.JsMlKemKeyPair();
  const keypair2 = new wasm.JsMlKemKeyPair();

  assertNotEqual(keypair1.publicKeyBase64, keypair2.publicKeyBase64,
    'Different keypairs should have different public keys');
});

test('Empty message encrypts and decrypts correctly', async () => {
  const { wasm } = await loadWasm();
  const { webcrypto } = await import('crypto');

  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = '';

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

  const combined = Buffer.concat([kemCiphertext, Buffer.from(nonce), Buffer.from(aesCiphertext)]);
  const content = combined.toString('base64');

  // Decrypt
  const combinedDecrypt = Buffer.from(content, 'base64');
  const aesCtDecrypt = combinedDecrypt.slice(KEM_CIPHERTEXT_SIZE + AES_NONCE_SIZE);
  const nonceDecrypt = combinedDecrypt.slice(KEM_CIPHERTEXT_SIZE, KEM_CIPHERTEXT_SIZE + AES_NONCE_SIZE);

  const decrypted = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonceDecrypt, tagLength: 128 }, aesKey, aesCtDecrypt
  );
  const decryptedMessage = new TextDecoder().decode(decrypted);

  assertEqual(decryptedMessage, message, 'Empty message should roundtrip correctly');
});

test('Large message (10KB) encrypts and decrypts correctly', async () => {
  const { wasm } = await loadWasm();
  const { webcrypto } = await import('crypto');

  const recipientKeypair = new wasm.JsMlKemKeyPair();
  const message = 'A'.repeat(10240); // 10KB message

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

  // Decrypt using recipient's key
  const recipientSS = Buffer.from(recipientKeypair.decapsulate(kemCiphertext.toString('base64')), 'base64');

  const recipientKeyMaterial = await webcrypto.subtle.importKey('raw', recipientSS, 'HKDF', false, ['deriveBits']);
  const recipientAesKeyBits = await webcrypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('pq-dm-v1') },
    recipientKeyMaterial, 256
  );
  const recipientAesKey = await webcrypto.subtle.importKey('raw', recipientAesKeyBits, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);

  const decrypted = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 }, recipientAesKey, aesCiphertext
  );
  const decryptedMessage = new TextDecoder().decode(decrypted);

  assertEqual(decryptedMessage.length, message.length, 'Large message should roundtrip correctly');
  assertEqual(decryptedMessage, message, 'Large message content should match');
});

// Run all tests
runTests();
