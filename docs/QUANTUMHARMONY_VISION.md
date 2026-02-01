# QuantumHarmony: Post-Quantum Infrastructure for the Quantum Era

## Executive Summary

QuantumHarmony is a Substrate-based blockchain designed to serve as critical infrastructure for the post-quantum era. It provides four core capabilities:

1. **Quantum Secure Messaging** - Triple Ratchet E2E encryption with forward secrecy
2. **Notarial Services** - Legally defensible digital attestation with SPHINCS+ signatures
3. **AI Model Governance** - Decentralized registry, audit trails, and compliance for AI systems
4. **QKD Network Bridge** - Trust anchor and governance layer connecting isolated quantum key distribution networks

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     QUANTUMHARMONY BLOCKCHAIN                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐│
│  │   QUANTUM     │  │   NOTARIAL    │  │   AI MODEL    │  │  QKD BRIDGE   ││
│  │   MESSENGER   │  │   SERVICES    │  │   GOVERNANCE  │  │  & NETWORK    ││
│  │               │  │               │  │               │  │  GOVERNANCE   ││
│  │ • Triple      │  │ • Ricardian   │  │ • Model       │  │ • Cross-domain││
│  │   Ratchet     │  │   Contracts   │  │   Registry    │  │   key routing ││
│  │ • ML-KEM-1024 │  │ • Document    │  │ • Training    │  │ • Trust anchor││
│  │ • Forward     │  │   Attestation │  │   Audit Trail │  │ • Policy      ││
│  │   Secrecy     │  │ • Witnesses   │  │ • ZK Proofs   │  │   enforcement ││
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘│
│          │                  │                  │                  │        │
│          └──────────────────┴──────────────────┴──────────────────┘        │
│                                     │                                       │
│                      ┌──────────────┴──────────────┐                       │
│                      │      CORE INFRASTRUCTURE    │                       │
│                      │                             │                       │
│                      │  • SPHINCS+ Signatures      │                       │
│                      │  • QMHY Token Economy       │                       │
│                      │  • Substrate Consensus      │                       │
│                      │  • QSSH Transport Layer     │                       │
│                      └─────────────────────────────┘                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Technologies

### Cryptographic Primitives

| Purpose | Algorithm | Standard | Security Level |
|---------|-----------|----------|----------------|
| Digital Signatures | SPHINCS+-256f | NIST FIPS 205 | 256-bit PQ |
| Key Encapsulation | ML-KEM-1024 | NIST FIPS 203 | 256-bit PQ |
| Key Exchange (hybrid) | X25519 | RFC 7748 | 128-bit classical |
| Symmetric Encryption | AES-256-GCM | NIST FIPS 197 | 256-bit (128-bit PQ) |
| Hash Function | SHA-3-256 | NIST FIPS 202 | 256-bit |
| Transport | QSSH (Falcon-512) | Custom | 128-bit PQ |

### Why Hybrid Key Exchange (ML-KEM-1024 + X25519)?

We use hybrid key exchange for defense in depth:

```
Final Key = KDF(ML-KEM-1024 shared secret || X25519 shared secret)
```

**Security Properties:**
- If ML-KEM is broken → X25519 still protects against classical attackers
- If X25519 is broken by quantum computers → ML-KEM still protects
- Attacker must break BOTH algorithms to compromise the key

**Historical Justification:**
- SIKE was a NIST PQC Round 3 finalist
- In 2022, SIKE was completely broken by classical attack
- Systems using pure SIKE would have been fully compromised
- Hybrid systems with SIKE + ECDH remained secure

**Transition Path:**
- 2025-2035: Hybrid (ML-KEM + X25519) - conservative/safe
- 2035+: Consider pure ML-KEM once algorithm has 20+ years of cryptanalysis

---

## Use Case 1: Quantum Secure Messaging

### Problem Statement

Current messaging systems face two critical vulnerabilities:
1. **Harvest Now, Decrypt Later (HNDL)**: Adversaries store encrypted traffic today to decrypt with future quantum computers
2. **No Forward Secrecy**: Compromise of long-term keys exposes all past messages

### Solution: Triple Ratchet Protocol

Following Signal's October 2025 upgrade, we implement a Triple Ratchet:

```
┌─────────────────────────────────────────────────────────────┐
│                    TRIPLE RATCHET                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Initial Key Exchange: PQXDH                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  X25519 ephemeral × X25519 identity                 │   │
│  │  +                                                   │   │
│  │  ML-KEM-1024 encapsulation                          │   │
│  │  =                                                   │   │
│  │  Hybrid shared secret                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           PARALLEL RATCHETS                         │   │
│  │                                                     │   │
│  │  ┌─────────────────┐    ┌─────────────────┐        │   │
│  │  │ Double Ratchet  │    │      SPQR       │        │   │
│  │  │   (X25519)      │    │  (ML-KEM-768)   │        │   │
│  │  │                 │    │                 │        │   │
│  │  │ • DH ratchet    │    │ • PQ ratchet    │        │   │
│  │  │ • Symmetric     │    │ • Sparse updates│        │   │
│  │  │   ratchet       │    │ • Erasure coded │        │   │
│  │  └────────┬────────┘    └────────┬────────┘        │   │
│  │           │                      │                 │   │
│  │           └──────────┬───────────┘                 │   │
│  │                      │                             │   │
│  │                      ▼                             │   │
│  │           ┌─────────────────────┐                  │   │
│  │           │  KDF(DR || SPQR)   │                  │   │
│  │           │  Message Key       │                  │   │
│  │           └─────────────────────┘                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| Confidentiality | AES-256-GCM with unique per-message keys |
| Forward Secrecy | Compromise of current key doesn't expose past messages |
| Post-Compromise Security | Future messages secure after compromise recovery |
| Quantum Resistance | ML-KEM protects against quantum adversaries |
| Hybrid Security | Must break both X25519 AND ML-KEM |

### On-Chain Integration

Messages are stored on-chain via the Mesh Forum pallet:
- Encrypted message content (only recipients can decrypt)
- SPHINCS+ signature for sender authentication
- Timestamp from blockchain consensus
- Optional: Zero-knowledge proof of message attributes

---

## Use Case 2: Notarial Services

### Problem Statement

Digital documents lack the legal weight of notarized physical documents because:
- Timestamps can be forged
- Signatures can be repudiated
- Document integrity cannot be proven
- Witness attestations are not cryptographically bound

### Solution: On-Chain Notarial Attestation

```rust
pub struct DocumentAttestation {
    /// SHA-3-256 hash of the document
    pub document_hash: [u8; 32],

    /// Category for regulatory compliance
    pub category: DocumentCategory,

    /// SPHINCS+ signature from the attesting party
    pub attestor_signature: SphincsSignature,

    /// Block number when attestation was recorded
    pub block_number: u64,

    /// Optional witness signatures
    pub witnesses: Vec<WitnessSignature>,

    /// Ricardian contract reference (if applicable)
    pub contract_reference: Option<ContractId>,
}

pub enum DocumentCategory {
    Contract,
    Will,
    PowerOfAttorney,
    RealEstate,
    Intellectual Property,
    Corporate,
    Identity,
    Medical,
    Custom(Vec<u8>),
}
```

### Ricardian Contracts

Human-readable contracts with machine-enforceable terms:

```rust
pub struct RicardianContract {
    /// Human-readable contract text
    pub prose: String,

    /// Structured clauses for machine parsing
    pub clauses: Vec<ContractClause>,

    /// All parties to the contract
    pub parties: Vec<ContractParty>,

    /// SPHINCS+ signatures from all parties
    pub signatures: Vec<SphincsSignature>,

    /// Amendment history
    pub amendments: Vec<ContractAmendment>,

    /// Current status
    pub status: ContractStatus,
}
```

### Legal Defensibility

SPHINCS+ signatures provide legal defensibility because:
1. **NIST Standardized** (FIPS 205) - Government-recognized standard
2. **Quantum Resistant** - Signatures remain valid against future quantum attacks
3. **Immutable Record** - Blockchain timestamp is tamper-proof
4. **Multi-Witness** - Multiple independent attestations strengthen validity

---

## Use Case 3: AI Model Governance

### Problem Statement

AI systems, especially foundation models, lack:
- Verifiable provenance (who trained it, on what data)
- Audit trails (what decisions were made, why)
- Access control (who can use/modify the model)
- Compliance verification (does it meet regulatory requirements)

### Solution: Decentralized AI Governance Registry

```
┌─────────────────────────────────────────────────────────────┐
│                 AI MODEL GOVERNANCE                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                MODEL REGISTRY                        │   │
│  │                                                     │   │
│  │  • Model hash (weights, architecture)               │   │
│  │  • Training data provenance                         │   │
│  │  • Version history                                  │   │
│  │  • Owner identity (SPHINCS+ public key)             │   │
│  │  • License terms                                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │               ACCESS CONTROL                         │   │
│  │                                                     │   │
│  │  • Role-based permissions (via smart contracts)     │   │
│  │  • SPHINCS+ signed access grants                    │   │
│  │  • Time-bounded access tokens                       │   │
│  │  • Revocation registry                              │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                AUDIT TRAIL                           │   │
│  │                                                     │   │
│  │  • Training run logs (on-chain hashes)              │   │
│  │  • Inference requests/responses (privacy-preserved) │   │
│  │  • Model updates and fine-tuning events             │   │
│  │  • Compliance check results                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            COMPLIANCE & ATTESTATION                  │   │
│  │                                                     │   │
│  │  • Zero-knowledge proofs of fairness metrics        │   │
│  │  • Bias detection attestations                      │   │
│  │  • Safety evaluation results                        │   │
│  │  • Regulatory compliance certificates               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Zero-Knowledge Compliance Proofs

AI developers can prove compliance without revealing proprietary information:

```rust
pub struct ComplianceProof {
    /// What is being proven
    pub claim: ComplianceClaim,

    /// Zero-knowledge proof (STARK-based)
    pub proof: StarkProof,

    /// Public inputs to the proof
    pub public_inputs: Vec<u8>,

    /// Attestor's signature
    pub attestor: SphincsSignature,
}

pub enum ComplianceClaim {
    /// Model achieves fairness metric without revealing test data
    FairnessMetric { metric: String, threshold: f64 },

    /// Training data meets requirements without revealing data
    DataProvenance { requirement: String },

    /// Model size/architecture within limits
    ResourceConstraints { max_params: u64, max_flops: u64 },

    /// Safety evaluation passed
    SafetyEvaluation { benchmark: String, score: f64 },
}
```

---

## Use Case 4: QKD Network Bridge & Governance

### Problem Statement

Quantum Key Distribution (QKD) networks are "islands":
- Bank A has a QKD network with its branches
- Government has a separate QKD network
- Telco B has another QKD network
- These networks cannot securely communicate with each other
- No trust framework for cross-domain key exchange

### Solution: QuantumHarmony as Trust Bridge

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      QKD NETWORK FEDERATION                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐      │
│   │  QKD Island │         │  QKD Island │         │  QKD Island │      │
│   │   (Bank A)  │         │   (Gov Net) │         │  (Telco B)  │      │
│   │             │         │             │         │             │      │
│   │ Local keys  │         │ Local keys  │         │ Local keys  │      │
│   │ Local trust │         │ Local trust │         │ Local trust │      │
│   └──────┬──────┘         └──────┬──────┘         └──────┬──────┘      │
│          │                       │                       │             │
│          │    QKD Link           │    QKD Link           │             │
│          ▼                       ▼                       ▼             │
│   ┌──────────────┐        ┌──────────────┐        ┌──────────────┐     │
│   │  Validator   │◄──────►│  Validator   │◄──────►│  Validator   │     │
│   │    Alice     │  QKD   │     Bob      │  QKD   │   Charlie    │     │
│   │  (Montreal)  │        │ (Beauharnois)│        │ (Frankfurt)  │     │
│   └──────┬───────┘        └──────┬───────┘        └──────┬───────┘     │
│          │                       │                       │             │
│          └───────────────────────┼───────────────────────┘             │
│                                  │                                      │
│                    ┌─────────────┴─────────────┐                       │
│                    │     QUANTUMHARMONY        │                       │
│                    │     CONSENSUS LAYER       │                       │
│                    │                           │                       │
│                    │  • Cross-domain key       │                       │
│                    │    routing decisions      │                       │
│                    │  • Policy enforcement     │                       │
│                    │  • Trust attestations     │                       │
│                    │  • Audit trail            │                       │
│                    │  • Governance DAO         │                       │
│                    └───────────────────────────┘                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Cross-Domain Key Routing

When Bank A needs to securely communicate with Telco B:

```rust
pub struct KeyRouteRequest {
    /// Source domain identifier
    pub source_domain: DomainId,

    /// Destination domain identifier
    pub dest_domain: DomainId,

    /// Requested key parameters
    pub key_params: KeyParameters,

    /// Requester's authorization proof
    pub auth_proof: SphincsSignature,
}

pub struct KeyRoute {
    /// Path through validator network
    pub path: Vec<ValidatorId>,

    /// Each hop's QKD session identifier
    pub qkd_sessions: Vec<QkdSessionId>,

    /// Attestations from each validator
    pub attestations: Vec<ValidatorAttestation>,

    /// Final shared key (encrypted to endpoints)
    pub encrypted_key: EncryptedKey,
}
```

### Governance DAO

Cross-domain key exchange requires governance:

```rust
pub struct QkdGovernanceProposal {
    /// Type of proposal
    pub proposal_type: ProposalType,

    /// Proposer
    pub proposer: AccountId,

    /// Voting period
    pub voting_ends: BlockNumber,

    /// Required approval threshold
    pub threshold: Percent,
}

pub enum ProposalType {
    /// Add new domain to federation
    AddDomain { domain: DomainId, validators: Vec<ValidatorId> },

    /// Remove domain from federation
    RemoveDomain { domain: DomainId },

    /// Update routing policy
    UpdatePolicy { policy: RoutingPolicy },

    /// Emergency key revocation
    EmergencyRevoke { affected_sessions: Vec<QkdSessionId> },

    /// Validator slashing for misbehavior
    SlashValidator { validator: ValidatorId, evidence: Evidence },
}
```

---

## Token Economics (QMHY)

### Token Utility

| Use Case | Token Flow |
|----------|------------|
| Messaging | Users pay tx fees to post messages on-chain |
| Notarial | Attestation fees paid to validators |
| AI Governance | Registry fees, access token purchases |
| QKD Bridge | Cross-domain routing fees |
| Staking | Validators stake QMHY for consensus participation |

### Supply & Distribution

| Parameter | Value |
|-----------|-------|
| Total Supply | 3,000,000 QMHY |
| Decimals | 18 |
| Genesis Validators | Alice, Bob, Charlie |
| Staking Rewards | Variable based on participation |

---

## Security Model

### Defense in Depth

```
Layer 1: Network Security
└── QSSH Falcon-512 tunnels (post-quantum transport)

Layer 2: Consensus Security
└── SPHINCS+ validator signatures (post-quantum finality)

Layer 3: Application Security
└── Triple Ratchet (hybrid PQ E2E encryption)

Layer 4: Data Security
└── On-chain immutability (tamper-proof storage)

Layer 5: Governance Security
└── Multi-sig, time-locks, DAO voting
```

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Harvest Now, Decrypt Later | ML-KEM-1024 key encapsulation |
| Quantum Computer Attack | All signatures/key exchange are PQ-safe |
| Validator Compromise | 2/3 consensus required, slashing for misbehavior |
| Network Eavesdropping | QSSH encrypted transport |
| Message Correlation | On-chain mixing, timing obfuscation |

---

## Roadmap

### Phase 1: Foundation (Current)
- [x] Substrate blockchain with SPHINCS+ signatures
- [x] Basic messaging via Mesh Forum pallet
- [x] QSSH transport layer
- [x] Web and desktop clients

### Phase 2: Triple Ratchet (Next)
- [ ] Implement PQXDH key exchange
- [ ] Implement SPQR (Sparse Post-Quantum Ratchet)
- [ ] Integrate with existing Mesh Forum
- [ ] Unified wallet + messenger UI

### Phase 3: Notarial Services
- [ ] Document attestation pallet
- [ ] Ricardian contract support
- [ ] Witness multi-sig
- [ ] Legal framework documentation

### Phase 4: AI Governance
- [ ] Model registry pallet
- [ ] Access control smart contracts
- [ ] STARK-based compliance proofs
- [ ] Audit trail indexer

### Phase 5: QKD Bridge
- [ ] Validator QKD integration
- [ ] Cross-domain routing protocol
- [ ] Governance DAO
- [ ] Federation onboarding

---

## Conclusion

QuantumHarmony is positioned to become critical infrastructure for the post-quantum era by providing:

1. **The only messenger** with true post-quantum E2E encryption AND forward secrecy
2. **Legally defensible** notarial services using NIST-standardized signatures
3. **The first decentralized** AI governance registry with zero-knowledge compliance
4. **The trust bridge** connecting isolated QKD networks into a federated quantum internet

This is not just a blockchain — it's the TCP/IP of the quantum era.

---

## References

- [Signal Triple Ratchet (SPQR)](https://signal.org/blog/spqr/)
- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/publications/detail/fips/203/final)
- [NIST FIPS 205 (SPHINCS+)](https://csrc.nist.gov/publications/detail/fips/205/final)
- [EuroQCI Initiative](https://digital-strategy.ec.europa.eu/en/policies/european-quantum-communication-infrastructure-euroqci)
- [Decentralized AI Governance (arxiv)](https://arxiv.org/html/2412.17114v3)
