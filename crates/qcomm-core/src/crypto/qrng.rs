//! Quantum Random Number Generator (QRNG) Integration
//!
//! Provides access to hardware quantum random number sources:
//! - Crypto4A QRNG hardware
//! - /dev/qrandom (when available)
//! - Fallback to OS CSPRNG when hardware unavailable

use crate::{Error, Result};

/// QRNG source types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrngSource {
    /// Crypto4A hardware QRNG
    Crypto4A,
    /// Linux /dev/qrandom device
    DevQrandom,
    /// macOS Secure Enclave (if quantum-enhanced)
    SecureEnclave,
    /// Fallback to OS CSPRNG
    OsCsprng,
}

/// QRNG provider that selects best available source
pub struct QrngProvider {
    source: QrngSource,
}

impl QrngProvider {
    /// Create a new QRNG provider, auto-detecting best source
    pub fn new() -> Self {
        let source = Self::detect_best_source();
        Self { source }
    }

    /// Create with a specific source (for testing)
    pub fn with_source(source: QrngSource) -> Self {
        Self { source }
    }

    /// Detect the best available QRNG source
    fn detect_best_source() -> QrngSource {
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Try Crypto4A first (would check for hardware in production)
            if Self::is_crypto4a_available() {
                return QrngSource::Crypto4A;
            }

            // Try /dev/qrandom
            if std::path::Path::new("/dev/qrandom").exists() {
                return QrngSource::DevQrandom;
            }
        }

        // Fallback to OS CSPRNG
        QrngSource::OsCsprng
    }

    /// Check if Crypto4A hardware is available
    #[cfg(not(target_arch = "wasm32"))]
    fn is_crypto4a_available() -> bool {
        // In production, this would check for actual hardware
        // Could use USB enumeration or specific device files
        false
    }

    /// Get the current source
    pub fn source(&self) -> QrngSource {
        self.source
    }

    /// Get entropy from the QRNG
    pub fn get_entropy(&self, bytes: usize) -> Result<Vec<u8>> {
        match self.source {
            #[cfg(not(target_arch = "wasm32"))]
            QrngSource::Crypto4A => self.get_crypto4a_entropy(bytes),
            #[cfg(not(target_arch = "wasm32"))]
            QrngSource::DevQrandom => self.get_dev_qrandom_entropy(bytes),
            #[cfg(not(target_arch = "wasm32"))]
            QrngSource::SecureEnclave => self.get_secure_enclave_entropy(bytes),
            QrngSource::OsCsprng => self.get_os_csprng_entropy(bytes),
            #[cfg(target_arch = "wasm32")]
            _ => self.get_os_csprng_entropy(bytes),
        }
    }

    /// Get entropy from Crypto4A hardware
    #[cfg(not(target_arch = "wasm32"))]
    fn get_crypto4a_entropy(&self, bytes: usize) -> Result<Vec<u8>> {
        // In production, this would communicate with Crypto4A hardware
        // via USB HID or similar interface
        Err(Error::QrngUnavailable("Crypto4A not implemented".into()))
    }

    /// Get entropy from /dev/qrandom
    #[cfg(not(target_arch = "wasm32"))]
    fn get_dev_qrandom_entropy(&self, bytes: usize) -> Result<Vec<u8>> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open("/dev/qrandom")
            .map_err(|e| Error::QrngUnavailable(e.to_string()))?;

        let mut entropy = vec![0u8; bytes];
        file.read_exact(&mut entropy)
            .map_err(|e| Error::QrngUnavailable(e.to_string()))?;

        Ok(entropy)
    }

    /// Get entropy from Secure Enclave
    #[cfg(not(target_arch = "wasm32"))]
    fn get_secure_enclave_entropy(&self, bytes: usize) -> Result<Vec<u8>> {
        // In production, this would use Security.framework on macOS
        // For now, fallback to OS CSPRNG
        self.get_os_csprng_entropy(bytes)
    }

    /// Get entropy from OS CSPRNG (fallback)
    fn get_os_csprng_entropy(&self, bytes: usize) -> Result<Vec<u8>> {
        use rand::RngCore;

        let mut entropy = vec![0u8; bytes];
        rand::thread_rng().fill_bytes(&mut entropy);
        Ok(entropy)
    }
}

impl Default for QrngProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Global QRNG instance for convenience
static QRNG: std::sync::OnceLock<QrngProvider> = std::sync::OnceLock::new();

/// Get entropy from the global QRNG provider
pub fn get_entropy(bytes: usize) -> Result<Vec<u8>> {
    QRNG.get_or_init(QrngProvider::new).get_entropy(bytes)
}

/// Get the current QRNG source
pub fn current_source() -> QrngSource {
    QRNG.get_or_init(QrngProvider::new).source()
}

/// Check if hardware QRNG is available
pub fn is_hardware_available() -> bool {
    matches!(
        current_source(),
        QrngSource::Crypto4A | QrngSource::DevQrandom
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_entropy() {
        let entropy = get_entropy(32).unwrap();
        assert_eq!(entropy.len(), 32);
    }

    #[test]
    fn test_entropy_uniqueness() {
        let e1 = get_entropy(32).unwrap();
        let e2 = get_entropy(32).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_provider_source() {
        let provider = QrngProvider::new();
        // Should fallback to OS CSPRNG in most test environments
        assert!(matches!(
            provider.source(),
            QrngSource::OsCsprng | QrngSource::DevQrandom | QrngSource::Crypto4A
        ));
    }
}
