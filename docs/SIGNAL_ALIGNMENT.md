# Signal SPQR Alignment and Design Rationale

This document explains how `qcomm-core` aligns with Signal's Sparse Post Quantum Ratchet (SPQR) architecture and where it intentionally diverges.

## Background

On October 2, 2025, Signal announced the **Sparse Post Quantum Ratchet (SPQR)** and **Triple Ratchet** protocol. This represents a significant advancement in post-quantum secure messaging.

Key points from Signal's announcement:
1. **Hybrid security**: Classical Double Ratchet + PQ ratchet, mixed via KDF
2. **Sparse ratcheting**: PQ key exchange at epoch boundaries, not every message
3. **Key insight**: Over-ratcheting can *increase* exposure under compromise
4. **Formal verification**: ProVerif, F*, hax integrated into CI

## Architectural Convergence

`qcomm-core` independently converged on the same architectural direction:

| Component | Signal | qcomm-core |
|-----------|--------|------------|
| Classical ratchet | ECDH Double Ratchet | Hash chain ratchet |
| PQ ratchet | ML-KEM-768 | ML-KEM-1024 |
| Key mixing | KDF | HKDF-SHA256 |
| Symmetric cipher | AES-256-GCM | AES-256-GCM |
| Forward secrecy | Hash advancement | Hash advancement |

Both designs implement a **Triple Ratchet** where:
1. A hash ratchet advances every message (per-message forward secrecy)
2. A PQ KEM ratchet advances at boundaries (post-quantum security)
3. Keys are mixed via KDF (hybrid security — attacker must break both)

## Signal's Key Insight: Sparse Ratcheting

Signal's research revealed a counter-intuitive finding:

> "While simulations that handled multiple epochs' secrets in parallel did generate new epochs more quickly, they actually made more messages vulnerable to a single breach."

This happens because:
- Pre-generating future epoch keys requires holding multiple pending decapsulation keys (DKs)
- If an attacker compromises the device, they gain access to all pending DKs
- This exposes not just the current epoch but all pending epochs

**Conclusion**: Sparse ratcheting (fewer, well-timed PQ ratchets) can be *more secure* than aggressive ratcheting.

### Implementation in qcomm-core

We implemented epoch tracking based on this insight:

```rust
pub enum RatchetMode {
    /// PQ ratchet on every key exchange (original behavior)
    PerMessage,

    /// PQ ratchet every N messages (Signal SPQR-style)
    Sparse { epoch_length: u32 },
}
```

With `RatchetConfig::sparse(50)`, the protocol:
- Advances the hash ratchet every message (per-message FS)
- Tracks message count within epochs
- Triggers PQ ratchet only at epoch boundaries

**Current limitation**: Full SPQR-style ratcheting requires exchanging KEM ciphertexts in message headers. Our implementation tracks epochs but relies on the existing key-change-based ratcheting. Future work will add ciphertext exchange.

## Intentional Divergences

### 1. Different Threat Model

**Signal optimizes for:**
- Billions of consumer users
- Mobile bandwidth constraints
- Heterogeneous client versions
- Passive network adversaries + device compromise

**qcomm-core targets:**
- Coordinated systems with audit requirements
- Verifiable state transitions (not just message confidentiality)
- Smaller networks with higher assurance requirements
- Research environments and governance systems

### 2. STARK Event Authentication

Signal's protocol focuses on message confidentiality and authenticity. qcomm-core adds **STARK-based zero-knowledge proofs** for event authentication:

```rust
pub struct StarkIdentity {
    secret_key: [u8; 32],
    public_key: [u8; 32],
}

impl StarkIdentity {
    pub fn sign_event(&self, event: &[u8]) -> StarkProof { ... }
    pub fn verify_event(&self, event: &[u8], proof: &StarkProof) -> bool { ... }
}
```

This enables:
- Proving that coordination happened correctly
- Audit trails with zero-knowledge properties
- Verifiable system state transitions

### 3. No Bandwidth Optimization

Signal implements:
- Erasure codes for chunking large KEM data
- ML-KEM Braid for parallel EK/CT transmission
- Careful bandwidth budgeting for mobile networks

qcomm-core does not implement these optimizations because:
- Target networks are smaller (lower aggregate bandwidth)
- Higher assurance requirements favor simplicity
- Research focus allows larger message sizes

### 4. Research-Grade Status

**Signal has:**
- Formal verification (ProVerif, F*, hax) in CI
- Production hardening over years
- Security audits and bug bounty programs

**qcomm-core is:**
- Research and experimental
- Not formally verified
- Requires additional security review for production use

## Implementation Comparison

### ML-KEM Key Exchange

Both use NIST FIPS 203 ML-KEM. Signal uses ML-KEM-768, we use ML-KEM-1024:

```rust
// qcomm-core: ML-KEM-1024
use ml_kem::MlKem1024Params;
type MlKem = Kem<MlKem1024Params>;

// Encapsulation key: 1568 bytes
// Decapsulation key: 3168 bytes
// Ciphertext: 1568 bytes
// Shared secret: 32 bytes
```

ML-KEM-1024 provides higher security margin at the cost of larger keys.

### Triple Ratchet Key Derivation

Both use HKDF to mix keys:

```rust
// Derive message key from chain key
let hk = Hkdf::<Sha256>::new(None, chain_key);
hk.expand(MESSAGE_INFO, &mut message_key)?;

// Mix PQ shared secret into root key
let hk = Hkdf::<Sha256>::new(Some(&root_key), shared_secret);
hk.expand(ROOT_INFO, &mut new_root_key)?;
```

### Forward Secrecy Mechanism

Both advance a symmetric chain on every message:

```rust
fn advance(&mut self) -> Result<MessageKey> {
    let hk = Hkdf::<Sha256>::new(None, self.chain_key.as_bytes());

    // Derive next chain key and message key
    hk.expand(CHAIN_INFO, &mut next_chain_key)?;
    hk.expand(MESSAGE_INFO, &mut message_key)?;

    self.chain_key = ChainKey(next_chain_key);
    self.counter += 1;

    Ok(MessageKey(message_key))
}
```

## Future Work

### Full SPQR Implementation

To match Signal's full SPQR:

1. **Add ciphertext to headers**: Include KEM ciphertext in `RatchetHeader`
2. **ML-KEM Braid**: Split EK transmission for bandwidth efficiency
3. **Explicit state machine**: Formalize ratchet states (SendingEK, ReceivingCT, etc.)

### Formal Verification

Following Signal's approach:
1. Model protocol in ProVerif
2. Extract F* models from Rust via hax
3. Prove security properties and panic-freedom in CI

### Downgrade Protection

Signal's approach for heterogeneous rollout:
1. Attach SPQR data to messages even when downgrade allowed
2. MAC the SPQR data with message-wide authentication
3. Lock in SPQR after first successful exchange

## References

1. [Signal: Sparse Post Quantum Ratchet (SPQR)](https://signal.org/blog/pqxdh/) — October 2025
2. [Signal: PQXDH Key Agreement](https://signal.org/docs/specifications/pqxdh/)
3. [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
4. [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
5. [Eurocrypt 2025: Triple Ratchet Foundations](https://eprint.iacr.org/) (Signal/PQShield/AIST/NYU)
6. [USENIX 2025: PQ Ratchet Protocol Analysis](https://www.usenix.org/) (Signal)

## Summary

| Aspect | Signal SPQR | qcomm-core | Rationale |
|--------|-------------|------------|-----------|
| **Architecture** | Triple Ratchet | Triple Ratchet | Convergent design |
| **KEM** | ML-KEM-768 | ML-KEM-1024 | Higher security margin |
| **Sparse ratcheting** | Full implementation | Epoch tracking | Future work for ciphertext exchange |
| **Bandwidth optimization** | Erasure codes, Braid | None | Different network scale |
| **Formal verification** | Yes (CI-enforced) | No | Research-grade |
| **STARK proofs** | No | Yes | Different threat model |
| **Target** | Consumer messaging | Coordinated systems | Different requirements |

The architectures are aligned. The differences are intentional, reflecting different threat models and use cases.
