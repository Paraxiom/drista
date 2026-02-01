//! Example: QuantumHarmony Integration via QSSH
//!
//! Demonstrates the full Drista + QuantumHarmony integration:
//! - Connecting to validators over QSSH (quantum-safe)
//! - Document attestation via notarial pallet
//! - Ricardian contract creation and signing
//!
//! Usage:
//!   1. Start QuantumHarmony validator with QSSH enabled
//!   2. Run: cargo run --example quantum_harmony_integration --features native-crypto

use qcomm_core::node::{
    QuantumHarmonyClient, QuantumHarmonyConfig, SecurityTier,
    DocumentCategory, ContractClause, ConnectionState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("====================================================");
    println!("  QuantumHarmony + Drista Integration Demo");
    println!("  Post-Quantum Secure Blockchain Access via QSSH");
    println!("====================================================\n");

    // 1. Configure QuantumHarmony client
    println!("1. Configuring QuantumHarmony client...");
    let config = QuantumHarmonyConfig {
        qssh_endpoint: "localhost:42".to_string(),
        http_endpoint: Some("http://localhost:9944".to_string()),
        username: whoami::username(),
        security_tier: SecurityTier::HardenedPQ, // T2: SPHINCS+ authenticated
        enable_qkd: true,
    };

    println!("   QSSH Endpoint: {}", config.qssh_endpoint);
    println!("   HTTP Fallback: {:?}", config.http_endpoint);
    println!("   Security Tier: {:?}", config.security_tier);
    println!("   QKD Enabled: {}", config.enable_qkd);

    let client = QuantumHarmonyClient::new(config);
    println!("   Initial State: {:?}", client.state().await);
    println!();

    // 2. Connect to validator
    println!("2. Connecting to QuantumHarmony validator...");
    match client.connect().await {
        Ok(()) => {
            let state = client.state().await;
            println!("   Connected! State: {:?}", state);

            if state == ConnectionState::QkdActive {
                println!("   QKD session established (T4+ security)");
            } else {
                println!("   Post-quantum security active");
            }
        }
        Err(e) => {
            println!("   Connection failed: {}", e);
            println!("   (This is expected if no validator is running)");
            println!();
            demo_offline_features().await?;
            return Ok(());
        }
    }
    println!();

    // 3. Query chain info
    println!("3. Querying chain information...");
    match client.get_chain_name().await {
        Ok(name) => println!("   Chain: {}", name),
        Err(e) => println!("   Chain query failed: {}", e),
    }
    match client.get_node_version().await {
        Ok(version) => println!("   Node Version: {}", version),
        Err(e) => println!("   Version query failed: {}", e),
    }
    match client.get_latest_block().await {
        Ok(block) => {
            println!("   Latest Block: #{}", block.number);
            println!("   Block Hash: {}...", &block.hash[..16.min(block.hash.len())]);
        }
        Err(e) => println!("   Block query failed: {}", e),
    }
    println!();

    // 4. Document attestation demo
    println!("4. Document Attestation (Notarial Pallet)...");

    // Simulate document hash (would be SHA-256 of actual document)
    let document_hash = "0x8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f1";
    let document_title = "Employment Agreement 2026";

    println!("   Document: {}", document_title);
    println!("   Hash: {}...", &document_hash[..20]);
    println!("   Category: Legal");

    match client.attest_document(
        document_hash,
        document_title,
        DocumentCategory::Legal,
        Some("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"),
    ).await {
        Ok(attestation) => {
            println!("   Attestation successful!");
            println!("   Block: {:?}", attestation.block_hash);
            println!("   Attester: {}", attestation.attester);
        }
        Err(e) => println!("   Attestation failed: {}", e),
    }
    println!();

    // 5. Verify document
    println!("5. Verifying document on-chain...");
    match client.verify_document(document_hash).await {
        Ok(Some(attestation)) => {
            println!("   Document verified on-chain!");
            println!("   Title: {}", attestation.title);
            println!("   Timestamp: {}", attestation.timestamp);
        }
        Ok(None) => println!("   Document not found on-chain"),
        Err(e) => println!("   Verification failed: {}", e),
    }
    println!();

    // 6. Ricardian contract demo
    println!("6. Ricardian Contract Creation...");

    let contract_title = "Service Agreement";
    let contract_terms = r#"
        This agreement is entered into by the parties below.
        Party A agrees to provide services. Party B agrees to pay.
        Terms are binding under digital signature law.
    "#;

    let clauses = vec![
        ContractClause {
            id: "1".to_string(),
            text: "Party A will deliver services within 30 days".to_string(),
            conditions: None,
        },
        ContractClause {
            id: "2".to_string(),
            text: "Party B will pay upon delivery".to_string(),
            conditions: Some("NET 30".to_string()),
        },
    ];

    let parties = vec![
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(), // Alice
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty".to_string(), // Bob
    ];

    println!("   Title: {}", contract_title);
    println!("   Clauses: {}", clauses.len());
    println!("   Parties: {}", parties.len());

    match client.create_contract(contract_title, contract_terms, clauses, parties).await {
        Ok(contract) => {
            println!("   Contract created!");
            println!("   Contract ID: {}", contract.contract_id);
            println!("   Status: {:?}", contract.status);
        }
        Err(e) => println!("   Contract creation failed: {}", e),
    }
    println!();

    // 7. Disconnect
    println!("7. Disconnecting...");
    client.disconnect().await?;
    println!("   Disconnected. Final state: {:?}", client.state().await);
    println!();

    println!("====================================================");
    println!("  Demo Complete!");
    println!("====================================================");
    println!();
    print_architecture();

    Ok(())
}

/// Demo features that work without a running validator
async fn demo_offline_features() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Offline Demo (No Validator Required) ===\n");

    // Security tier explanation
    println!("Security Tiers Available:");
    println!("  T1 (PostQuantum)      - SPHINCS+ signatures only");
    println!("  T2 (HardenedPQ)       - Default, SPHINCS+ with enhanced key derivation");
    println!("  T3 (EntropyEnhanced)  - Hardware QRNG for entropy");
    println!("  T4 (QuantumSecured)   - QKD-secured session keys");
    println!("  T5 (HybridQuantum)    - Full QKD + PQC + classical hybrid");
    println!();

    // Document categories
    println!("Document Categories for Notarial Pallet:");
    let categories = [
        DocumentCategory::Academic,
        DocumentCategory::Legal,
        DocumentCategory::Contract,
        DocumentCategory::IntellectualProperty,
        DocumentCategory::Identity,
        DocumentCategory::Financial,
        DocumentCategory::Medical,
        DocumentCategory::Other,
    ];
    for cat in categories {
        println!("  - {}", cat.as_str());
    }
    println!();

    print_architecture();

    Ok(())
}

fn print_architecture() {
    println!("Architecture Overview:");
    println!();
    println!("  +---------------------------+");
    println!("  |      Drista Wallet        |");
    println!("  |  (QuantumHarmonyClient)   |");
    println!("  +-------------+-------------+");
    println!("                |");
    println!("                | QSSH (Port 42)");
    println!("                | SPHINCS+ Authentication");
    println!("                | AES-256-GCM Encryption");
    println!("                |");
    println!("  +-------------v-------------+");
    println!("  |  QuantumHarmony Validator |");
    println!("  |  - Notarial Pallet (21)   |");
    println!("  |  - Ricardian Pallet (20)  |");
    println!("  |  - SPHINCS+ Keystore      |");
    println!("  +-------------+-------------+");
    println!("                |");
    println!("                | Substrate P2P");
    println!("                | QSSH Inter-Validator");
    println!("                |");
    println!("  +-------------v-------------+");
    println!("  |    Other Validators       |");
    println!("  |    (Consensus Network)    |");
    println!("  +---------------------------+");
    println!();
    println!("Key Features:");
    println!("  - All RPC calls travel over QSSH (quantum-safe)");
    println!("  - SPHINCS+ signatures for all transactions");
    println!("  - Optional QKD enhancement for T4+ security");
    println!("  - HTTP fallback for development/testing");
}
