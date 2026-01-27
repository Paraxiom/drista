//! Handshake Protocol
//!
//! Manages session establishment between peers, supporting both
//! PQ-Triple-Ratchet (preferred) and Noise Protocol (BitChat fallback).

use crate::crypto::pq::{MlKemKeyPair, MlKemPublicKey, SphincsPublicKey};
use crate::crypto::noise::NoiseSession;
use crate::crypto::ratchet::PqTripleRatchet;
use crate::protocol::PeerCapabilities;
use crate::{Error, Result, Identity};
use serde::{Deserialize, Serialize};

/// Handshake state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting to initiate
    New,
    /// Sent initial message
    Initiated,
    /// Received initial, sending response
    Responding,
    /// Complete
    Complete,
    /// Failed
    Failed,
}

/// Handshake message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Initial hello with capabilities
    Hello {
        /// Sender's capabilities
        capabilities: PeerCapabilities,
        /// Ephemeral ML-KEM public key (for PQC)
        mlkem_pk: Option<Vec<u8>>,
        /// Ephemeral X25519 public key (for Noise fallback)
        x25519_pk: Option<Vec<u8>>,
        /// SPHINCS+ identity key
        identity_pk: Vec<u8>,
    },
    /// Response with key material
    Response {
        /// Responder's capabilities
        capabilities: PeerCapabilities,
        /// ML-KEM ciphertext (for PQC)
        mlkem_ct: Option<Vec<u8>>,
        /// X25519 public key (for Noise)
        x25519_pk: Option<Vec<u8>>,
        /// SPHINCS+ identity key
        identity_pk: Vec<u8>,
        /// Signature over transcript
        signature: Vec<u8>,
    },
    /// Final confirmation
    Confirm {
        /// Signature over transcript
        signature: Vec<u8>,
    },
}

/// Handshake session
pub struct Handshake {
    /// Our identity
    our_identity: Identity,
    /// Their identity (once known)
    their_identity: Option<Identity>,
    /// Current state
    state: HandshakeState,
    /// Are we the initiator?
    initiator: bool,
    /// Our ephemeral ML-KEM keypair
    mlkem_keypair: Option<MlKemKeyPair>,
    /// Negotiated: use PQC
    use_pqc: bool,
    /// Handshake transcript for signing
    transcript: Vec<u8>,
}

impl Handshake {
    /// Create as initiator
    pub fn initiator(identity: Identity) -> Self {
        Self {
            our_identity: identity,
            their_identity: None,
            state: HandshakeState::New,
            initiator: true,
            mlkem_keypair: None,
            use_pqc: true,
            transcript: Vec::new(),
        }
    }

    /// Create as responder
    pub fn responder(identity: Identity) -> Self {
        Self {
            our_identity: identity,
            their_identity: None,
            state: HandshakeState::New,
            initiator: false,
            mlkem_keypair: None,
            use_pqc: true,
            transcript: Vec::new(),
        }
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete
    }

    /// Create initial hello message
    pub fn create_hello(&mut self, our_caps: &PeerCapabilities) -> Result<HandshakeMessage> {
        if self.state != HandshakeState::New {
            return Err(Error::KeyExchange("Invalid state for hello".into()));
        }

        // Generate ephemeral ML-KEM keypair
        let mlkem = MlKemKeyPair::generate()?;
        let mlkem_pk = mlkem.public_key().as_bytes().to_vec();
        self.mlkem_keypair = Some(mlkem);

        let msg = HandshakeMessage::Hello {
            capabilities: our_caps.clone(),
            mlkem_pk: Some(mlkem_pk),
            x25519_pk: None, // Would add for Noise fallback
            identity_pk: self.our_identity.public_key().as_bytes().to_vec(),
        };

        // Update transcript
        let serialized = bincode::serialize(&msg)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.transcript.extend(&serialized);

        self.state = HandshakeState::Initiated;
        Ok(msg)
    }

    /// Process received hello and create response
    pub fn process_hello(
        &mut self,
        msg: HandshakeMessage,
        our_caps: &PeerCapabilities,
    ) -> Result<HandshakeMessage> {
        if self.state != HandshakeState::New {
            return Err(Error::KeyExchange("Invalid state for processing hello".into()));
        }

        let (their_caps, mlkem_pk_bytes, identity_pk_bytes) = match &msg {
            HandshakeMessage::Hello {
                capabilities,
                mlkem_pk,
                identity_pk,
                ..
            } => (capabilities.clone(), mlkem_pk.clone(), identity_pk.clone()),
            _ => return Err(Error::InvalidMessage("Expected Hello".into())),
        };

        // Store their identity
        let identity_pk = SphincsPublicKey::from_bytes(&identity_pk_bytes)?;
        self.their_identity = Some(Identity::from_public_key(identity_pk));

        // Negotiate capabilities
        self.use_pqc = our_caps.pq_ratchet && their_caps.pq_ratchet;

        // Generate our ML-KEM keypair
        let mlkem = MlKemKeyPair::generate()?;

        // Encapsulate to their public key if PQC
        let mlkem_ct = if self.use_pqc {
            if let Some(pk_bytes) = mlkem_pk_bytes {
                let their_pk = MlKemPublicKey::from_bytes(&pk_bytes)?;
                let (ct, _ss) = their_pk.encapsulate()?;
                Some(ct.as_bytes().to_vec())
            } else {
                None
            }
        } else {
            None
        };

        self.mlkem_keypair = Some(mlkem);

        // Update transcript
        let serialized = bincode::serialize(&msg)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.transcript.extend(&serialized);

        // Sign transcript
        let signature = self.our_identity.sign(&self.transcript)?;

        let response = HandshakeMessage::Response {
            capabilities: our_caps.clone(),
            mlkem_ct,
            x25519_pk: None,
            identity_pk: self.our_identity.public_key().as_bytes().to_vec(),
            signature,
        };

        // Update transcript with response
        let serialized = bincode::serialize(&response)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.transcript.extend(&serialized);

        self.state = HandshakeState::Responding;
        Ok(response)
    }

    /// Process response and create confirmation
    pub fn process_response(&mut self, msg: HandshakeMessage) -> Result<HandshakeMessage> {
        if self.state != HandshakeState::Initiated {
            return Err(Error::KeyExchange("Invalid state for processing response".into()));
        }

        let (their_caps, _mlkem_ct, identity_pk_bytes, their_sig) = match &msg {
            HandshakeMessage::Response {
                capabilities,
                mlkem_ct,
                identity_pk,
                signature,
                ..
            } => (capabilities.clone(), mlkem_ct.clone(), identity_pk.clone(), signature.clone()),
            _ => return Err(Error::InvalidMessage("Expected Response".into())),
        };

        // Store their identity
        let identity_pk = SphincsPublicKey::from_bytes(&identity_pk_bytes)?;
        self.their_identity = Some(Identity::from_public_key(identity_pk.clone()));

        // Verify their signature
        if !identity_pk.verify(&self.transcript, &their_sig)? {
            self.state = HandshakeState::Failed;
            return Err(Error::InvalidSignature);
        }

        // Update negotiated caps
        self.use_pqc = their_caps.pq_ratchet;

        // Update transcript
        let serialized = bincode::serialize(&msg)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.transcript.extend(&serialized);

        // Sign complete transcript
        let signature = self.our_identity.sign(&self.transcript)?;

        let confirm = HandshakeMessage::Confirm { signature };

        self.state = HandshakeState::Complete;
        Ok(confirm)
    }

    /// Process confirmation to complete handshake
    pub fn process_confirm(&mut self, msg: HandshakeMessage) -> Result<()> {
        if self.state != HandshakeState::Responding {
            return Err(Error::KeyExchange("Invalid state for processing confirm".into()));
        }

        let their_sig = match &msg {
            HandshakeMessage::Confirm { signature } => signature.clone(),
            _ => return Err(Error::InvalidMessage("Expected Confirm".into())),
        };

        // Verify signature
        let their_identity = self.their_identity.as_ref()
            .ok_or_else(|| Error::KeyExchange("No their identity".into()))?;

        if !their_identity.verify(&self.transcript, &their_sig)? {
            self.state = HandshakeState::Failed;
            return Err(Error::InvalidSignature);
        }

        self.state = HandshakeState::Complete;
        Ok(())
    }

    /// Get their identity after handshake
    pub fn their_identity(&self) -> Option<&Identity> {
        self.their_identity.as_ref()
    }

    /// Check if PQC was negotiated
    pub fn uses_pqc(&self) -> bool {
        self.use_pqc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_creation() {
        let identity = Identity::generate().unwrap();
        let hs = Handshake::initiator(identity);
        assert_eq!(hs.state(), HandshakeState::New);
    }

    #[test]
    fn test_create_hello() {
        let identity = Identity::generate().unwrap();
        let mut hs = Handshake::initiator(identity);
        let caps = PeerCapabilities::default();

        let msg = hs.create_hello(&caps).unwrap();
        assert!(matches!(msg, HandshakeMessage::Hello { .. }));
        assert_eq!(hs.state(), HandshakeState::Initiated);
    }
}
