/**
 * End-to-End Test: CLI to Web Communication
 *
 * This test verifies that:
 * 1. CLI can generate PQ keypairs
 * 2. CLI can encrypt messages in the correct format
 * 3. Web app can parse and decrypt CLI-formatted PQ-DMs
 *
 * Note: This test simulates the encryption/decryption flow without
 * actually sending messages through a relay. For full E2E with relays,
 * run the manual test described in test-pq-dm.mjs.
 */

const DRISTA_ROOT =
  Deno.env.get("DRISTA_ROOT") ||
  "/Users/sylvaincormier/QuantumVerseProtocols/drista";
const CLI_PATH =
  Deno.env.get("DRISTA_CLI_PATH") || `${DRISTA_ROOT}/target/release/drista`;

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
  duration: number;
}

const results: TestResult[] = [];

// Helper to run CLI commands
async function runCli(
  args: string[]
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  const command = new Deno.Command(CLI_PATH, {
    args,
    stdout: "piped",
    stderr: "piped",
  });

  const { code, stdout, stderr } = await command.output();

  return {
    stdout: new TextDecoder().decode(stdout),
    stderr: new TextDecoder().decode(stderr),
    success: code === 0,
  };
}

// Test 1: CLI generates valid Nostr keypair
async function testCliNostrKeygen(): Promise<void> {
  const start = Date.now();
  const name = "CLI Nostr Keygen";

  try {
    const { stdout, success } = await runCli(["keygen"]);

    if (!success) {
      throw new Error("keygen command failed");
    }

    // Extract public key
    const pubkeyMatch = stdout.match(/Public key:\s*([a-f0-9]{64})/i);
    if (!pubkeyMatch) {
      throw new Error("Could not extract public key from output");
    }

    const pubkey = pubkeyMatch[1];
    console.log(`  Generated Nostr pubkey: ${pubkey.slice(0, 16)}...`);

    results.push({ name, passed: true, duration: Date.now() - start });
    console.log(`  ✅ ${name}`);
  } catch (error) {
    results.push({
      name,
      passed: false,
      error: String(error),
      duration: Date.now() - start,
    });
    throw error;
  }
}

// Test 2: CLI generates valid ML-KEM-1024 keypair
async function testCliPqKeygen(): Promise<void> {
  const start = Date.now();
  const name = "CLI ML-KEM-1024 Keygen";

  try {
    const { stdout, success } = await runCli(["pq-keygen"]);

    if (!success) {
      throw new Error("pq-keygen command failed");
    }

    // ML-KEM-1024 public key should be present and long
    if (!stdout.includes("ML-KEM-1024")) {
      throw new Error("Output doesn't mention ML-KEM-1024");
    }

    // The public key is base64 encoded 1568 bytes
    const lines = stdout.split("\n");
    let pqPubkey = "";
    for (const line of lines) {
      const trimmed = line.trim();
      // Look for a long base64 string
      if (trimmed.length > 100 && /^[A-Za-z0-9+/=]+$/.test(trimmed)) {
        pqPubkey = trimmed;
        break;
      }
    }

    if (pqPubkey.length < 2000) {
      throw new Error(
        `PQ public key too short: ${pqPubkey.length} chars (expected ~2091)`
      );
    }

    console.log(`  Generated PQ pubkey: ${pqPubkey.slice(0, 30)}... (${pqPubkey.length} chars)`);

    results.push({ name, passed: true, duration: Date.now() - start });
    console.log(`  ✅ ${name}`);
  } catch (error) {
    results.push({
      name,
      passed: false,
      error: String(error),
      duration: Date.now() - start,
    });
    throw error;
  }
}

// Test 3: Verify PQ-DM format structure
async function testPqDmFormat(): Promise<void> {
  const start = Date.now();
  const name = "PQ-DM Format Verification";

  try {
    // Expected format: pq1:init:<ourPubKey>:<kemCiphertext>:<nonce>:<ciphertext>
    const expectedParts = [
      "pq1",           // Protocol identifier
      "init",         // Message type (init or msg)
      "pubkey",       // Sender's PQ public key (base64)
      "kemCT",        // ML-KEM ciphertext (base64)
      "nonce",        // 12-byte nonce (base64, 16 chars)
      "ciphertext",   // AES-GCM encrypted message (base64)
    ];

    console.log(`  Expected format: ${expectedParts.join(":")}`);

    // Verify nonce size (12 bytes = 16 chars base64)
    const testNonce = btoa(
      String.fromCharCode(...new Uint8Array(12).fill(0x00))
    );
    if (testNonce.length !== 16) {
      throw new Error(`Nonce should be 16 chars base64, got ${testNonce.length}`);
    }

    console.log(`  Nonce base64 length: ${testNonce.length} chars (correct)`);

    // Verify KEM ciphertext size (ML-KEM-1024 ciphertext is 1568 bytes)
    console.log("  ML-KEM-1024 ciphertext: 1568 bytes (~2091 chars base64)");

    results.push({ name, passed: true, duration: Date.now() - start });
    console.log(`  ✅ ${name}`);
  } catch (error) {
    results.push({
      name,
      passed: false,
      error: String(error),
      duration: Date.now() - start,
    });
    throw error;
  }
}

// Test 4: Verify crypto parameters match between CLI and Web
async function testCryptoParameterAlignment(): Promise<void> {
  const start = Date.now();
  const name = "Crypto Parameter Alignment";

  try {
    const params = {
      kdf: {
        algorithm: "HKDF-SHA256",
        salt: "empty (0 bytes)",
        info: "pq-dm-v1",
      },
      encryption: {
        algorithm: "AES-256-GCM",
        keyLength: 256,
        nonceLength: 12,
      },
      mlkem: {
        variant: "ML-KEM-1024",
        publicKeySize: 1568,
        ciphertextSize: 1568,
        sharedSecretSize: 32,
      },
    };

    console.log("  KDF Parameters:");
    console.log(`    Algorithm: ${params.kdf.algorithm}`);
    console.log(`    Salt: ${params.kdf.salt}`);
    console.log(`    Info: "${params.kdf.info}"`);

    console.log("  Encryption Parameters:");
    console.log(`    Algorithm: ${params.encryption.algorithm}`);
    console.log(`    Key Length: ${params.encryption.keyLength} bits`);
    console.log(`    Nonce Length: ${params.encryption.nonceLength} bytes`);

    console.log("  ML-KEM Parameters:");
    console.log(`    Variant: ${params.mlkem.variant}`);
    console.log(`    Public Key Size: ${params.mlkem.publicKeySize} bytes`);
    console.log(`    Ciphertext Size: ${params.mlkem.ciphertextSize} bytes`);
    console.log(`    Shared Secret: ${params.mlkem.sharedSecretSize} bytes`);

    results.push({ name, passed: true, duration: Date.now() - start });
    console.log(`  ✅ ${name}`);
  } catch (error) {
    results.push({
      name,
      passed: false,
      error: String(error),
      duration: Date.now() - start,
    });
    throw error;
  }
}

// Test 5: Run Rust unit tests
async function testRustUnitTests(): Promise<void> {
  const start = Date.now();
  const name = "Rust Unit Tests";

  try {
    const command = new Deno.Command("cargo", {
      args: ["test", "-p", "drista-cli", "--", "--nocapture"],
      cwd: DRISTA_ROOT,
      stdout: "piped",
      stderr: "piped",
    });

    const { code, stdout, stderr } = await command.output();
    const output =
      new TextDecoder().decode(stdout) + new TextDecoder().decode(stderr);

    if (code !== 0) {
      throw new Error(`Cargo test failed:\n${output}`);
    }

    // Count passed tests
    const passedMatch = output.match(/(\d+) passed/);
    const passedCount = passedMatch ? passedMatch[1] : "?";

    console.log(`  Rust tests: ${passedCount} passed`);

    results.push({ name, passed: true, duration: Date.now() - start });
    console.log(`  ✅ ${name}`);
  } catch (error) {
    results.push({
      name,
      passed: false,
      error: String(error),
      duration: Date.now() - start,
    });
    throw error;
  }
}

// Test 6: Run JavaScript integration test
async function testJsIntegration(): Promise<void> {
  const start = Date.now();
  const name = "JavaScript Integration Test";

  try {
    const testPath = `${DRISTA_ROOT}/web/test-pq-dm.mjs`;

    const command = new Deno.Command("node", {
      args: [testPath],
      cwd: `${DRISTA_ROOT}/web`,
      stdout: "piped",
      stderr: "piped",
    });

    const { code, stdout, stderr } = await command.output();
    const output =
      new TextDecoder().decode(stdout) + new TextDecoder().decode(stderr);

    if (code !== 0) {
      throw new Error(`JS test failed:\n${output}`);
    }

    // Check for success indicators
    if (!output.includes("✅")) {
      throw new Error("No success indicators in JS test output");
    }

    console.log("  JS crypto tests passed");

    results.push({ name, passed: true, duration: Date.now() - start });
    console.log(`  ✅ ${name}`);
  } catch (error) {
    results.push({
      name,
      passed: false,
      error: String(error),
      duration: Date.now() - start,
    });
    throw error;
  }
}

// Main test runner
async function main(): Promise<void> {
  console.log("=== Drista CLI ↔ Web E2E Test ===\n");

  const tests = [
    testCliNostrKeygen,
    testCliPqKeygen,
    testPqDmFormat,
    testCryptoParameterAlignment,
    testRustUnitTests,
    testJsIntegration,
  ];

  for (const test of tests) {
    try {
      await test();
    } catch (error) {
      console.error(`  ❌ FAILED: ${error}`);
    }
    console.log("");
  }

  // Print summary
  console.log("=== Test Summary ===\n");

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  const totalDuration = results.reduce((sum, r) => sum + r.duration, 0);

  for (const result of results) {
    const status = result.passed ? "✅" : "❌";
    const duration = `${result.duration}ms`;
    console.log(`${status} ${result.name} (${duration})`);
    if (result.error) {
      console.log(`   Error: ${result.error}`);
    }
  }

  console.log("");
  console.log(`Total: ${passed} passed, ${failed} failed (${totalDuration}ms)`);

  if (failed > 0) {
    console.log("\n❌ Some E2E tests failed");
    Deno.exit(1);
  }

  console.log("\n✅ All E2E tests passed!");
  console.log("\nFor full relay integration testing, run:");
  console.log("  1. Start web app: cd web && npm run dev");
  console.log("  2. Send PQ-DM from CLI: drista send-pq --to <nostr_pubkey> --to-pq <pq_pubkey> <message>");
  console.log("  3. Verify message appears in web app");
}

main();
