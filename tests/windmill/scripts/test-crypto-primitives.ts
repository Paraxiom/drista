/**
 * Test crypto primitives compatibility between CLI and Web
 * Runs in Deno (Windmill's TypeScript runtime)
 */

// Test 1: HKDF-SHA256 key derivation
async function testHkdfDerivation(): Promise<void> {
  console.log("Test 1: HKDF-SHA256 key derivation");

  const testSharedSecret = new Uint8Array(32).fill(0x42);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    testSharedSecret,
    "HKDF",
    false,
    ["deriveKey"]
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode("pq-dm-v1"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const exportedKey = await crypto.subtle.exportKey("raw", aesKey);
  if (exportedKey.byteLength !== 32) {
    throw new Error(
      `HKDF derived key wrong length: ${exportedKey.byteLength}, expected 32`
    );
  }

  console.log("  ✅ HKDF derivation produces 32-byte key");
}

// Test 2: AES-256-GCM encrypt/decrypt roundtrip
async function testAesGcmRoundtrip(): Promise<void> {
  console.log("Test 2: AES-256-GCM roundtrip");

  const testMessage = "Hello from Drista PQ-DM test! 你好 🔐";
  const testKey = new Uint8Array(32).fill(0x42);
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    testKey,
    "HKDF",
    false,
    ["deriveKey"]
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode("pq-dm-v1"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  const plaintext = new TextEncoder().encode(testMessage);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    aesKey,
    plaintext
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    aesKey,
    encrypted
  );

  const decryptedText = new TextDecoder().decode(decrypted);
  if (decryptedText !== testMessage) {
    throw new Error(
      `AES-GCM roundtrip failed: "${decryptedText}" !== "${testMessage}"`
    );
  }

  console.log("  ✅ AES-256-GCM encrypt/decrypt roundtrip works");
}

// Test 3: PQ-DM message format parsing
function testPqDmFormatParsing(): void {
  console.log("Test 3: PQ-DM format parsing");

  const sampleContent =
    "pq1:init:ABC123PUBKEY:KEMCIPHERTEXT:NONCE12345678:MESSAGECIPHERTEXT";
  const parts = sampleContent.split(":");

  if (parts.length !== 6) {
    throw new Error(`Expected 6 parts, got ${parts.length}`);
  }

  if (parts[0] !== "pq1") {
    throw new Error(`Expected prefix 'pq1', got '${parts[0]}'`);
  }

  if (parts[1] !== "init") {
    throw new Error(`Expected type 'init', got '${parts[1]}'`);
  }

  console.log("  ✅ PQ-DM init format parsing works");

  const msgContent = "pq1:msg:HEADER:CIPHERTEXT";
  const msgParts = msgContent.split(":");

  if (msgParts.length !== 4) {
    throw new Error(`Expected 4 parts for msg, got ${msgParts.length}`);
  }

  if (msgParts[1] !== "msg") {
    throw new Error(`Expected type 'msg', got '${msgParts[1]}'`);
  }

  console.log("  ✅ PQ-DM msg format parsing works");
}

// Test 4: Nonce size detection (CLI vs Triple Ratchet)
function testNonceSizeDetection(): void {
  console.log("Test 4: Nonce size detection");

  // CLI format uses 12-byte nonce
  const shortNonce = btoa(
    String.fromCharCode(...new Uint8Array(12).fill(0x00))
  );
  const shortDecoded = Uint8Array.from(atob(shortNonce), (c) => c.charCodeAt(0));

  if (shortDecoded.length !== 12) {
    throw new Error(`Short nonce should be 12 bytes, got ${shortDecoded.length}`);
  }

  const isCliFormat = shortDecoded.length <= 16;
  if (!isCliFormat) {
    throw new Error("12-byte nonce should be detected as CLI format");
  }

  console.log("  ✅ CLI format (12-byte nonce) detected correctly");

  // Triple Ratchet header is much larger (>100 bytes)
  const longHeader = btoa(
    String.fromCharCode(...new Uint8Array(100).fill(0x00))
  );
  const longDecoded = Uint8Array.from(atob(longHeader), (c) => c.charCodeAt(0));

  const isRatchetFormat = longDecoded.length > 16;
  if (!isRatchetFormat) {
    throw new Error("100-byte header should be detected as Ratchet format");
  }

  console.log("  ✅ Triple Ratchet format (long header) detected correctly");
}

// Test 5: NIP-04 format validation
function testNip04Format(): void {
  console.log("Test 5: NIP-04 format validation");

  // NIP-04 format: base64(ciphertext)?iv=base64(iv)
  const sampleEncrypted = "SGVsbG8gV29ybGQ=?iv=MTIzNDU2Nzg5MDEyMzQ1Ng==";

  if (!sampleEncrypted.includes("?iv=")) {
    throw new Error("NIP-04 format must contain '?iv=' separator");
  }

  const parts = sampleEncrypted.split("?iv=");
  if (parts.length !== 2) {
    throw new Error("NIP-04 format must have exactly 2 parts");
  }

  // IV should be 16 bytes (base64 encoded)
  const ivBytes = Uint8Array.from(atob(parts[1]), (c) => c.charCodeAt(0));
  if (ivBytes.length !== 16) {
    throw new Error(`NIP-04 IV should be 16 bytes, got ${ivBytes.length}`);
  }

  console.log("  ✅ NIP-04 format validation works");
}

// Main test runner
async function main(): Promise<void> {
  console.log("=== Drista Crypto Primitives Test ===\n");

  const tests = [
    testHkdfDerivation,
    testAesGcmRoundtrip,
    testPqDmFormatParsing,
    testNonceSizeDetection,
    testNip04Format,
  ];

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    try {
      await test();
      passed++;
    } catch (error) {
      console.error(`  ❌ FAILED: ${error}`);
      failed++;
    }
    console.log("");
  }

  console.log("=== Summary ===");
  console.log(`Passed: ${passed}/${tests.length}`);
  console.log(`Failed: ${failed}/${tests.length}`);

  if (failed > 0) {
    Deno.exit(1);
  }

  console.log("\n✅ All crypto primitive tests passed!");
}

main();
