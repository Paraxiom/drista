//! Integration tests for QSSH + Drista
//!
//! Tests the integration between the QSSH library and Drista's transport layer.

use qcomm_core::transport::qssh::{
    QsshTransport, QsshConfig, SessionState, TransportTier,
    PqAlgorithm, SecurityTier,
};
use qcomm_core::transport::{Transport, TransportCapability};
use qcomm_core::crypto::qkd::{QkdClient, QkdProtocol, enhance_key};

/// Test that QSSH transport initializes correctly with QSSH library types
#[tokio::test]
async fn test_qssh_transport_with_library_types() {
    let config = QsshConfig {
        listen_port: 4242,
        pq_algorithm: PqAlgorithm::Falcon512,
        security_tier: SecurityTier::HardenedPQ,
        quantum_native: true,
        ..Default::default()
    };

    let transport = QsshTransport::new(config);

    // Verify capabilities include PostQuantum
    let caps = transport.capabilities();
    assert!(caps.contains(&TransportCapability::PostQuantum));
    assert!(caps.contains(&TransportCapability::Send));
    assert!(caps.contains(&TransportCapability::Receive));

    // Verify security tier
    assert_eq!(transport.security_tier(), SecurityTier::HardenedPQ);
}

/// Test security tier to transport tier conversion
#[test]
fn test_security_tier_mapping() {
    // T2 (HardenedPQ) should map to PQ-SECURED
    assert_eq!(
        TransportTier::from_security_tier(SecurityTier::HardenedPQ),
        TransportTier::PqSecured
    );

    // T1 (PostQuantum) should also map to PQ-SECURED
    assert_eq!(
        TransportTier::from_security_tier(SecurityTier::PostQuantum),
        TransportTier::PqSecured
    );

    // T4 (QuantumSecured with QKD) should map to PQ-SECURED
    assert_eq!(
        TransportTier::from_security_tier(SecurityTier::QuantumSecured),
        TransportTier::PqSecured
    );

    // Display names for UI
    assert_eq!(TransportTier::PqSecured.display_name(), "PQ-SECURED");
    assert_eq!(TransportTier::Hybrid.display_name(), "HYBRID");
    assert_eq!(TransportTier::Tls.display_name(), "TLS");
}

/// Test config conversion to QSSH library config
#[test]
fn test_config_to_qssh_lib_config() {
    let config = QsshConfig {
        listen_port: 2222,
        pq_algorithm: PqAlgorithm::Falcon512,
        security_tier: SecurityTier::QuantumSecured,
        qkd_endpoint: Some("https://qkd.example.com".into()),
        ..Default::default()
    };

    let lib_config = config.to_lib_config("192.168.1.100:2222", "alice");

    assert_eq!(lib_config.server, "192.168.1.100:2222");
    assert_eq!(lib_config.username, "alice");
    assert_eq!(lib_config.pq_algorithm, PqAlgorithm::Falcon512);
    assert_eq!(lib_config.security_tier, SecurityTier::QuantumSecured);
    assert!(lib_config.use_qkd);
    assert!(lib_config.quantum_native);
}

/// Test QKD key enhancement with Drista's QKD client
#[tokio::test]
async fn test_qkd_key_enhancement() {
    let client = QkdClient::new(QkdProtocol::BB84);

    // Add some simulated keys
    client.add_simulated_keys(3).await;
    assert_eq!(client.keys_available().await, 3);

    // Get a key and enhance a classical key
    let qkd_key = client.get_key().await.unwrap().unwrap();
    let classical_key = vec![0xAA; 32];

    let enhanced = enhance_key(&classical_key, Some(&qkd_key));

    // Enhanced key should be different from classical
    assert_ne!(enhanced, classical_key);
    assert_eq!(enhanced.len(), 32);
}

/// Test QKD with QSSH endpoint configuration
#[tokio::test]
#[cfg(feature = "native-crypto")]
async fn test_qkd_qssh_bridge() {
    use qcomm_core::crypto::qkd::qssh_bridge;

    // Check if QSSH QKD endpoint is configured
    let is_configured = qssh_bridge::is_qssh_qkd_configured();

    // In test environment, it's likely not configured
    if !is_configured {
        // Create a client with QSSH endpoint
        let client = QkdClient::with_qssh_endpoint("https://qkd.test.local");
        assert_eq!(client.protocol(), QkdProtocol::EtsiNetwork);
    }
}

/// Test transport connection lifecycle
#[tokio::test]
async fn test_transport_lifecycle() {
    let config = QsshConfig::default();
    let mut transport = QsshTransport::new(config);

    // Initially not connected
    assert!(!transport.is_connected().await);

    // Connect (starts listener)
    transport.connect().await.unwrap();
    assert!(transport.is_connected().await);

    // Verify active sessions is empty (no peers connected)
    let sessions = transport.active_sessions().await;
    assert!(sessions.is_empty());

    // Disconnect
    transport.disconnect().await.unwrap();
}

/// Test multiple security tier configurations
#[tokio::test]
async fn test_all_security_tiers() {
    let tiers = [
        SecurityTier::PostQuantum,
        SecurityTier::HardenedPQ,
        SecurityTier::EntropyEnhanced,
        SecurityTier::QuantumSecured,
        SecurityTier::HybridQuantum,
    ];

    for tier in tiers {
        let config = QsshConfig {
            security_tier: tier,
            ..Default::default()
        };

        let transport = QsshTransport::new(config);
        assert_eq!(transport.security_tier(), tier);

        // All PQ tiers should map to PQ-SECURED
        let transport_tier = TransportTier::from_security_tier(tier);
        assert_eq!(transport_tier, TransportTier::PqSecured);
    }
}

/// Test algorithm selection
#[test]
fn test_pq_algorithm_selection() {
    // Test Falcon512 (default)
    let config = QsshConfig {
        pq_algorithm: PqAlgorithm::Falcon512,
        ..Default::default()
    };
    let lib_config = config.to_lib_config("host:22", "user");
    assert_eq!(lib_config.pq_algorithm, PqAlgorithm::Falcon512);

    // Test SphincsPlus (recommended for macOS)
    let config = QsshConfig {
        pq_algorithm: PqAlgorithm::SphincsPlus,
        ..Default::default()
    };
    let lib_config = config.to_lib_config("host:22", "user");
    assert_eq!(lib_config.pq_algorithm, PqAlgorithm::SphincsPlus);

    // Test Falcon1024 (NIST Level 5)
    let config = QsshConfig {
        pq_algorithm: PqAlgorithm::Falcon1024,
        ..Default::default()
    };
    let lib_config = config.to_lib_config("host:22", "user");
    assert_eq!(lib_config.pq_algorithm, PqAlgorithm::Falcon1024);
}
