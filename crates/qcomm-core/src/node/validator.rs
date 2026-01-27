//! Validator Mode for QuantumHarmony

use crate::{Error, Result, Identity, Fingerprint};
use serde::{Deserialize, Serialize};

/// Validator status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Not a validator
    None,
    /// Registered but not active
    Waiting,
    /// Active validator
    Active,
    /// Jailed (penalized)
    Jailed,
}

/// Validator statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorStats {
    /// Blocks authored
    pub blocks_authored: u64,
    /// Forum posts
    pub forum_posts: u64,
    /// Uptime percentage
    pub uptime: f64,
    /// Total rewards earned
    pub total_rewards: u64,
    /// Current era points
    pub era_points: u32,
}

/// Validator identity on chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorIdentity {
    /// SPHINCS+ public key (on-chain identity)
    pub identity_key: Vec<u8>,
    /// Fingerprint derived from identity
    pub fingerprint: String,
    /// Display name (optional)
    pub display_name: Option<String>,
    /// Website (optional)
    pub website: Option<String>,
    /// Riot/Matrix handle (optional)
    pub riot: Option<String>,
}

/// Validator mode configuration
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Enable block authoring
    pub author_blocks: bool,
    /// Stake amount (in planck)
    pub stake: u128,
    /// Commission percentage (0-100)
    pub commission: u8,
    /// Session keys path
    pub session_keys_path: Option<String>,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            author_blocks: false,
            stake: 0,
            commission: 10,
            session_keys_path: None,
        }
    }
}

/// Validator mode for the light client
pub struct ValidatorMode {
    /// Configuration
    config: ValidatorConfig,
    /// Our validator identity
    identity: Option<ValidatorIdentity>,
    /// Current status
    status: ValidatorStatus,
    /// Statistics
    stats: ValidatorStats,
}

impl ValidatorMode {
    /// Create a new validator mode
    pub fn new(config: ValidatorConfig) -> Self {
        Self {
            config,
            identity: None,
            status: ValidatorStatus::None,
            stats: ValidatorStats::default(),
        }
    }

    /// Initialize from identity
    pub fn from_identity(identity: &Identity, config: ValidatorConfig) -> Self {
        let validator_identity = ValidatorIdentity {
            identity_key: identity.public_key().as_bytes().to_vec(),
            fingerprint: identity.fingerprint().to_hex(),
            display_name: None,
            website: None,
            riot: None,
        };

        Self {
            config,
            identity: Some(validator_identity),
            status: ValidatorStatus::None,
            stats: ValidatorStats::default(),
        }
    }

    /// Get current status
    pub fn status(&self) -> ValidatorStatus {
        self.status
    }

    /// Get statistics
    pub fn stats(&self) -> &ValidatorStats {
        &self.stats
    }

    /// Get validator identity
    pub fn identity(&self) -> Option<&ValidatorIdentity> {
        self.identity.as_ref()
    }

    /// Set display name
    pub fn set_display_name(&mut self, name: impl Into<String>) {
        if let Some(ref mut identity) = self.identity {
            identity.display_name = Some(name.into());
        }
    }

    /// Register as validator
    pub async fn register(&mut self) -> Result<()> {
        if self.identity.is_none() {
            return Err(Error::Config("No identity set".into()));
        }

        if self.config.stake == 0 {
            return Err(Error::Config("No stake configured".into()));
        }

        // In production, would submit validator.register extrinsic
        tracing::info!(
            "Registering validator with stake {} and commission {}%",
            self.config.stake,
            self.config.commission
        );

        self.status = ValidatorStatus::Waiting;
        Ok(())
    }

    /// Unregister as validator
    pub async fn unregister(&mut self) -> Result<()> {
        if self.status == ValidatorStatus::None {
            return Err(Error::Config("Not a validator".into()));
        }

        // In production, would submit validator.unregister extrinsic
        tracing::info!("Unregistering validator");

        self.status = ValidatorStatus::None;
        Ok(())
    }

    /// Update validator status from chain
    pub async fn refresh_status(&mut self) -> Result<()> {
        // In production, would query chain state
        // For now, simulate
        Ok(())
    }

    /// Update statistics from chain
    pub async fn refresh_stats(&mut self) -> Result<()> {
        // In production, would query chain state
        Ok(())
    }

    /// Rotate session keys
    pub async fn rotate_session_keys(&self) -> Result<Vec<u8>> {
        // In production, would call author_rotateKeys RPC
        // and submit session.setKeys extrinsic

        let dummy_keys = vec![0u8; 128];
        Ok(dummy_keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_mode() {
        let config = ValidatorConfig::default();
        let mode = ValidatorMode::new(config);
        assert_eq!(mode.status(), ValidatorStatus::None);
    }

    #[test]
    fn test_from_identity() {
        let identity = Identity::generate().unwrap();
        let config = ValidatorConfig::default();
        let mode = ValidatorMode::from_identity(&identity, config);

        assert!(mode.identity().is_some());
        assert_eq!(
            mode.identity().unwrap().fingerprint,
            identity.fingerprint().to_hex()
        );
    }
}
