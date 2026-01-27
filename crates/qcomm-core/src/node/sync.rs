//! Block Synchronization

use super::BlockHeader;
use crate::Result;
use std::collections::VecDeque;

/// Sync state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Not syncing
    Idle,
    /// Downloading headers
    DownloadingHeaders,
    /// Verifying headers
    Verifying,
    /// Complete
    Synced,
}

/// Header chain for light client verification
pub struct HeaderChain {
    /// Headers in order
    headers: VecDeque<BlockHeader>,
    /// Maximum headers to keep
    max_headers: usize,
    /// Finalized block number
    finalized: u64,
}

impl HeaderChain {
    /// Create a new header chain
    pub fn new(max_headers: usize) -> Self {
        Self {
            headers: VecDeque::new(),
            max_headers,
            finalized: 0,
        }
    }

    /// Get the latest header
    pub fn latest(&self) -> Option<&BlockHeader> {
        self.headers.back()
    }

    /// Get the finalized block number
    pub fn finalized(&self) -> u64 {
        self.finalized
    }

    /// Add a new header
    pub fn push(&mut self, header: BlockHeader) -> Result<()> {
        // Verify parent hash
        if let Some(latest) = self.headers.back() {
            if header.parent_hash != latest.hash {
                return Err(crate::Error::NodeSync(
                    "Parent hash mismatch".to_string(),
                ));
            }
        }

        self.headers.push_back(header);

        // Prune old headers
        while self.headers.len() > self.max_headers {
            self.headers.pop_front();
        }

        Ok(())
    }

    /// Update finalized block
    pub fn set_finalized(&mut self, block_number: u64) {
        self.finalized = block_number;

        // Remove headers before finalized
        while let Some(header) = self.headers.front() {
            if header.number < block_number.saturating_sub(10) {
                self.headers.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get header by number
    pub fn get(&self, number: u64) -> Option<&BlockHeader> {
        self.headers.iter().find(|h| h.number == number)
    }

    /// Get header by hash
    pub fn get_by_hash(&self, hash: &str) -> Option<&BlockHeader> {
        self.headers.iter().find(|h| h.hash == hash)
    }

    /// Check if block is in chain
    pub fn contains(&self, number: u64) -> bool {
        self.headers.iter().any(|h| h.number == number)
    }

    /// Get chain length
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

/// Block sync manager
pub struct SyncManager {
    /// Header chain
    chain: HeaderChain,
    /// Current sync state
    state: SyncState,
    /// Target block number
    target: u64,
}

impl SyncManager {
    /// Create a new sync manager
    pub fn new() -> Self {
        Self {
            chain: HeaderChain::new(1000),
            state: SyncState::Idle,
            target: 0,
        }
    }

    /// Get current state
    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Get sync progress (0.0 - 1.0)
    pub fn progress(&self) -> f64 {
        if self.target == 0 {
            return 1.0;
        }

        let current = self.chain.latest().map(|h| h.number).unwrap_or(0);
        (current as f64) / (self.target as f64)
    }

    /// Start sync to target
    pub fn start_sync(&mut self, target: u64) {
        self.target = target;
        self.state = SyncState::DownloadingHeaders;
    }

    /// Process a batch of headers
    pub fn process_headers(&mut self, headers: Vec<BlockHeader>) -> Result<()> {
        self.state = SyncState::Verifying;

        for header in headers {
            self.chain.push(header)?;
        }

        // Check if synced
        if let Some(latest) = self.chain.latest() {
            if latest.number >= self.target {
                self.state = SyncState::Synced;
            } else {
                self.state = SyncState::DownloadingHeaders;
            }
        }

        Ok(())
    }

    /// Handle finality notification
    pub fn handle_finality(&mut self, block_number: u64) {
        self.chain.set_finalized(block_number);
    }

    /// Get the header chain
    pub fn chain(&self) -> &HeaderChain {
        &self.chain
    }
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(number: u64, parent_hash: &str) -> BlockHeader {
        BlockHeader {
            hash: format!("0x{:064x}", number),
            number,
            parent_hash: parent_hash.to_string(),
            state_root: String::new(),
            extrinsics_root: String::new(),
            timestamp: 0,
        }
    }

    #[test]
    fn test_header_chain() {
        let mut chain = HeaderChain::new(100);

        let h1 = make_header(1, "0x0");
        let h2 = make_header(2, &h1.hash);

        chain.push(h1).unwrap();
        chain.push(h2).unwrap();

        assert_eq!(chain.len(), 2);
        assert_eq!(chain.latest().unwrap().number, 2);
    }

    #[test]
    fn test_sync_manager() {
        let mut manager = SyncManager::new();
        assert_eq!(manager.state(), SyncState::Idle);

        manager.start_sync(100);
        assert_eq!(manager.state(), SyncState::DownloadingHeaders);
    }
}
