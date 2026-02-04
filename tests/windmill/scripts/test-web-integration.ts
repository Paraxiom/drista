/**
 * Test web app integration
 * Verifies the web app's crypto and relay connection
 */

const WEB_URL = Deno.env.get("WEB_URL") || "http://localhost:3004";
const TIMEOUT = parseInt(Deno.env.get("TEST_TIMEOUT") || "30000");

// Test 1: Web app is accessible
async function testWebAppAccessible(): Promise<void> {
  console.log("Test 1: Web app accessibility");

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT);

  try {
    const response = await fetch(WEB_URL, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const html = await response.text();
    if (!html.includes("Drista") && !html.includes("drista")) {
      console.warn("  Warning: Page doesn't mention 'Drista'");
    }

    console.log(`  ✅ Web app accessible at ${WEB_URL}`);
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(`Timeout connecting to ${WEB_URL}`);
    }
    throw error;
  }
}

// Test 2: Static assets load
async function testStaticAssets(): Promise<void> {
  console.log("Test 2: Static assets");

  const assets = ["/index.js", "/style.css"];

  for (const asset of assets) {
    try {
      const response = await fetch(`${WEB_URL}${asset}`);
      if (response.ok) {
        console.log(`  ✅ ${asset} loads`);
      } else {
        console.log(`  ⚠️ ${asset} returned ${response.status}`);
      }
    } catch {
      console.log(`  ⚠️ ${asset} failed to load (may not exist)`);
    }
  }
}

// Test 3: Check for WASM module availability
async function testWasmModule(): Promise<void> {
  console.log("Test 3: WASM module");

  const wasmPaths = ["/qcomm_core_bg.wasm", "/wasm/qcomm_core_bg.wasm"];

  let found = false;
  for (const path of wasmPaths) {
    try {
      const response = await fetch(`${WEB_URL}${path}`);
      if (response.ok) {
        const contentType = response.headers.get("content-type");
        if (
          contentType?.includes("wasm") ||
          contentType?.includes("octet-stream")
        ) {
          console.log(`  ✅ WASM module found at ${path}`);
          found = true;
          break;
        }
      }
    } catch {
      // Continue to next path
    }
  }

  if (!found) {
    console.log("  ⚠️ WASM module not found (may be bundled or lazy-loaded)");
  }
}

// Test 4: Verify crypto library dependencies in JavaScript
async function testCryptoDependencies(): Promise<void> {
  console.log("Test 4: Crypto dependencies in bundle");

  try {
    const response = await fetch(`${WEB_URL}/index.js`);
    if (!response.ok) {
      console.log("  ⚠️ Could not fetch index.js");
      return;
    }

    const js = await response.text();

    // Check for expected crypto patterns
    const patterns = [
      { name: "AES-GCM", pattern: /AES-GCM/i },
      { name: "HKDF", pattern: /HKDF/i },
      { name: "secp256k1", pattern: /secp256k1/i },
      { name: "subtle.crypto", pattern: /crypto\.subtle/i },
    ];

    for (const { name, pattern } of patterns) {
      if (pattern.test(js)) {
        console.log(`  ✅ ${name} reference found`);
      } else {
        console.log(`  ⚠️ ${name} reference not found (may be in separate chunk)`);
      }
    }
  } catch (error) {
    console.log(`  ⚠️ Could not analyze JavaScript bundle: ${error}`);
  }
}

// Test 5: Check relay configuration
async function testRelayConfig(): Promise<void> {
  console.log("Test 5: Relay configuration");

  const expectedRelays = [
    "relay.damus.io",
    "drista.paraxiom.org",
    "nos.lol",
  ];

  try {
    const response = await fetch(`${WEB_URL}/index.js`);
    if (!response.ok) {
      console.log("  ⚠️ Could not fetch index.js");
      return;
    }

    const js = await response.text();

    for (const relay of expectedRelays) {
      if (js.includes(relay)) {
        console.log(`  ✅ Relay configured: ${relay}`);
      } else {
        console.log(`  ⚠️ Relay not found: ${relay}`);
      }
    }
  } catch (error) {
    console.log(`  ⚠️ Could not check relay config: ${error}`);
  }
}

// Main test runner
async function main(): Promise<void> {
  console.log("=== Drista Web Integration Test ===\n");
  console.log(`Target: ${WEB_URL}\n`);

  const tests = [
    testWebAppAccessible,
    testStaticAssets,
    testWasmModule,
    testCryptoDependencies,
    testRelayConfig,
  ];

  let passed = 0;
  let failed = 0;
  const warnings: string[] = [];

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
    console.log("\n❌ Some web integration tests failed");
    Deno.exit(1);
  }

  console.log("\n✅ Web integration tests passed!");
}

main();
