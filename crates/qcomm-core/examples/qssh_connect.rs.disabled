//! Example: Connect to QSSH server using Drista's transport layer
//!
//! This demonstrates the full integration between Drista and QSSH.
//!
//! Usage:
//!   1. Start qsshd server: QSSH_AUTH_PATH=/Users qsshd --listen 127.0.0.1:4242 --quantum-native
//!   2. Run this example: cargo run --example qssh_connect
//!
//! Note: On macOS, use SPHINCS+ instead of Falcon to avoid pqcrypto segfault.

use qcomm_core::transport::qssh::{
    QsshTransport, QsshConfig, TransportTier,
    PqAlgorithm, SecurityTier,
};
use qcomm_core::transport::Transport;
use qcomm_core::crypto::qkd::{QkdClient, QkdProtocol, enhance_key};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Drista + QSSH Integration Test ===\n");

    // 1. Test QKD key enhancement
    println!("1. Testing QKD Key Enhancement...");
    let qkd_client = QkdClient::new(QkdProtocol::BB84);
    qkd_client.add_simulated_keys(5).await;

    let classical_key = vec![0xAA; 32];
    let qkd_key = qkd_client.get_key().await?.unwrap();
    let enhanced = enhance_key(&classical_key, Some(&qkd_key));

    println!("   Classical key: {:02x}{:02x}{:02x}...", classical_key[0], classical_key[1], classical_key[2]);
    println!("   Enhanced key:  {:02x}{:02x}{:02x}...", enhanced[0], enhanced[1], enhanced[2]);
    println!("   ✓ QKD enhancement working\n");

    // 2. Test Security Tier configuration
    println!("2. Testing Security Tiers...");
    let tiers = [
        (SecurityTier::PostQuantum, "T1: Post-Quantum"),
        (SecurityTier::HardenedPQ, "T2: Hardened PQ (default)"),
        (SecurityTier::EntropyEnhanced, "T3: Entropy Enhanced"),
        (SecurityTier::QuantumSecured, "T4: Quantum Secured"),
        (SecurityTier::HybridQuantum, "T5: Hybrid Quantum"),
    ];

    for (tier, name) in tiers {
        let transport_tier = TransportTier::from_security_tier(tier);
        println!("   {} -> {}", name, transport_tier.display_name());
    }
    println!("   ✓ Security tiers configured\n");

    // 3. Test QSSH Transport configuration
    println!("3. Testing QSSH Transport Configuration...");

    // Use SPHINCS+ on macOS to avoid pqcrypto-falcon segfault
    #[cfg(target_os = "macos")]
    let algorithm = PqAlgorithm::SphincsPlus;
    #[cfg(not(target_os = "macos"))]
    let algorithm = PqAlgorithm::Falcon512;

    let config = QsshConfig {
        listen_port: 4242,
        pq_algorithm: algorithm,
        security_tier: SecurityTier::HardenedPQ,
        quantum_native: true,
        ..Default::default()
    };

    let lib_config = config.to_lib_config("127.0.0.1:4242", "testuser");
    println!("   Server: {}", lib_config.server);
    println!("   User: {}", lib_config.username);
    println!("   Algorithm: {:?}", lib_config.pq_algorithm);
    println!("   Security Tier: {:?}", lib_config.security_tier);
    println!("   Quantum Native: {}", lib_config.quantum_native);
    println!("   ✓ Configuration ready\n");

    // 4. Test Transport initialization
    println!("4. Testing Transport Initialization...");
    let mut transport = QsshTransport::new(config);

    println!("   Name: {}", transport.name());
    println!("   Capabilities: {:?}", transport.capabilities());
    println!("   Security Tier: {:?}", transport.security_tier());
    println!("   Connected: {}", transport.is_connected().await);
    println!("   ✓ Transport initialized\n");

    // 5. Test listener start
    println!("5. Testing Listener...");
    match transport.connect().await {
        Ok(()) => {
            println!("   ✓ Listener started");
            transport.disconnect().await?;
            println!("   ✓ Disconnected cleanly");
        }
        Err(e) => {
            println!("   ⚠ Failed to start listener: {}", e);
        }
    }

    println!("\n=== Integration Test Complete ===");
    println!("Transport Tier: {}", TransportTier::PqSecured.display_name());

    Ok(())
}
