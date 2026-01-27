# Security Model

Threat model and security analysis for the QuantumHarmony bridge transport.

## Defense in Depth

Security is layered — compromise of any single layer does not break confidentiality:

| Layer | QSSH Path (native) | TLS Path (browser) |
|-------|--------------------|--------------------|
| Transport | Falcon-512 + AES-256-GCM | TLS 1.3 (classical) |
| Application | NIP-04 ECDH + AES-CBC | NIP-04 ECDH + AES-CBC |
| Identity | STARK proofs (Winterfell ZK) | STARK proofs (Winterfell ZK) |
| Persistence | On-chain (Mesh Forum pallet) | On-chain (Mesh Forum pallet) |

### Layer Details

**Transport (outer envelope):**
- QSSH path: Falcon-512 lattice-based signatures for authentication, AES-256-GCM for symmetric encryption. Resistant to quantum attacks (NIST PQC Round 3 finalist).
- TLS path: TLS 1.3 with classical cryptography. Vulnerable to future quantum computers but protects against current classical adversaries.

**Application (message content):**
- NIP-04: ECDH shared secret (secp256k1) + AES-256-CBC. E2E encrypted — neither the bridge nor the transport layer can read message content.
- This layer is independent of transport. Even over plain `ws://`, message content is encrypted.

**Identity (proof of authorship):**
- STARK proofs (Winterfell ZK library): Zero-knowledge proof that the sender knows the private key, without revealing it. Verified by recipients.
- Nostr Schnorr signatures (secp256k1): Standard NIP-01 event signatures.

**Persistence (tamper resistance):**
- Events posted to Substrate Mesh Forum pallet, committed to chain via consensus.
- Once on-chain, events cannot be modified or deleted without consensus.

## Threat Model

### Adversary Capabilities

| Adversary | Can do | Cannot do |
|-----------|--------|-----------|
| Network observer | See encrypted traffic, connection timing, IP addresses | Read message content (NIP-04 encrypted) |
| Quantum adversary (future) | Break TLS 1.3, break secp256k1 ECDH | Break Falcon-512 (lattice-based), break AES-256 |
| Compromised bridge | See NIP-04 ciphertext, connection metadata | Decrypt messages (no access to private keys) |
| Compromised validator | Modify chain state (with consensus) | Forge NIP-01 signatures or STARK proofs |

### Attack Scenarios

**1. Man-in-the-Middle (MITM)**

| Path | Protection |
|------|-----------|
| QSSH | Falcon-512 host key verification (TOFU model). Client verifies server's public key on first connection. |
| TLS | Certificate verification (self-signed initially, Let's Encrypt for production). |
| Both | NIP-04 E2E encryption — even a successful MITM cannot read content. |

**2. Harvest Now, Decrypt Later (HNDL)**

A quantum adversary records encrypted traffic today and decrypts it when quantum computers are available.

| Path | Risk |
|------|------|
| QSSH | **Low.** Falcon-512 is post-quantum. Recorded traffic cannot be decrypted by quantum computers. |
| TLS | **Transport exposed.** TLS 1.3 session keys could be recovered. However, NIP-04 content remains protected by AES-256 (quantum-resistant for symmetric key sizes). The ECDH key exchange in NIP-04 is vulnerable, meaning a quantum adversary could derive the shared secret from public keys on-chain. |

**Mitigation:** Use QSSH path for sensitive communications. The TLS fallback is acceptable for browsers where QSSH is not yet available, given that:
- NIP-04 adds a second encryption layer
- STARK proofs provide quantum-resistant identity verification
- The practical timeline for breaking secp256k1 with quantum computers is estimated at 10+ years

**3. Compromised Bridge Node**

If an attacker gains access to a bridge process:
- They see NIP-04 ciphertext (cannot decrypt without user private keys)
- They see connection metadata (which pubkeys are talking)
- They can drop or delay messages (availability attack)
- They cannot forge events (Schnorr signature verification)
- They cannot modify on-chain history (consensus required)

**4. Rogue Validator**

A validator controlling their bridge + Substrate node:
- Can censor messages from their node (not post to chain)
- Cannot forge messages from other users (signature verification)
- Cannot unilaterally rewrite chain history (2/3 consensus threshold)
- Other validators will still relay messages from other paths

## Comparison: Before vs After

| Property | Before (plain ws://) | After (QSSH + TLS) |
|----------|---------------------|---------------------|
| Transport encryption | None | Falcon-512 (PQ) or TLS 1.3 |
| Exposed ports | 7777 (public) | 4242 (QSSH) + 7778 (TLS) |
| Bridge binding | 0.0.0.0 | 127.0.0.1 |
| MITM resistance | NIP-04 only | Transport auth + NIP-04 |
| Quantum resistance | NIP-04 AES only | Full (QSSH path) |
| Metadata protection | None | Encrypted tunnel |

### What Improves

- **Transport confidentiality:** Traffic is encrypted in transit (previously plaintext WebSocket).
- **Bridge isolation:** Bridge only accepts local connections, reducing attack surface.
- **Quantum resistance (QSSH path):** Falcon-512 protects against future quantum adversaries.
- **Metadata protection:** Connection metadata is hidden inside the encrypted tunnel.

### What Stays the Same

- **Message confidentiality:** NIP-04 E2E encryption was already in place.
- **Identity verification:** STARK proofs and Schnorr signatures unchanged.
- **Chain persistence:** Mesh Forum pallet storage unchanged.

### What the TLS Fallback Leaks

When using the browser TLS path instead of QSSH:
- **Connection timing:** When connections are made/dropped.
- **IP addresses:** Client IP visible to nginx/validator.
- **Traffic volume:** Amount of data exchanged (encrypted, but volume visible).
- **NOT leaked:** Message content (NIP-04), sender/recipient identity within encrypted content.

## Future Improvements

1. **Full PQ browser path:** Falcon-512 WASM bindings would allow browsers to connect directly to qsshd, eliminating TLS fallback.
2. **NIP-04 PQ upgrade:** Replace secp256k1 ECDH with a PQ KEM (e.g., Kyber) for the application-layer encryption.
3. **Let's Encrypt:** Replace self-signed certs with proper CA-signed certificates.
4. **Host key pinning:** Distribute qsshd host key fingerprints out-of-band for TOFU verification.
5. **Tor integration:** Optional onion routing for IP address privacy.
