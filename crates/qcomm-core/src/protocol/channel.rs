//! Channel Management
//!
//! Handles both direct message channels and group channels.

use crate::{Error, Result, Fingerprint};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Channel types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    /// Direct message between two users
    Direct,
    /// Group channel
    Group,
    /// On-chain forum channel
    Forum,
    /// AI agent channel
    Agent,
}

/// Channel member with permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMember {
    /// Member fingerprint
    pub fingerprint: String,
    /// Display name
    pub name: Option<String>,
    /// Is admin
    pub is_admin: bool,
    /// Can post
    pub can_post: bool,
    /// Joined timestamp
    pub joined_at: u64,
}

/// A chat channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    /// Unique channel ID
    pub id: String,
    /// Channel name (for groups) or recipient fingerprint (for DM)
    pub name: String,
    /// Channel type
    pub channel_type: ChannelType,
    /// Members
    pub members: HashMap<String, ChannelMember>,
    /// Created timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Unread message count
    pub unread_count: u32,
    /// Is encrypted
    pub encrypted: bool,
    /// Uses PQC
    pub pqc_enabled: bool,
    /// On-chain (for forum channels)
    pub on_chain: bool,
}

impl Channel {
    /// Create a direct message channel
    pub fn direct(our_fingerprint: &str, their_fingerprint: &str) -> Self {
        let now = Self::now();

        let mut members = HashMap::new();
        members.insert(
            our_fingerprint.to_string(),
            ChannelMember {
                fingerprint: our_fingerprint.to_string(),
                name: None,
                is_admin: true,
                can_post: true,
                joined_at: now,
            },
        );
        members.insert(
            their_fingerprint.to_string(),
            ChannelMember {
                fingerprint: their_fingerprint.to_string(),
                name: None,
                is_admin: true,
                can_post: true,
                joined_at: now,
            },
        );

        Self {
            id: Self::dm_id(our_fingerprint, their_fingerprint),
            name: their_fingerprint.to_string(),
            channel_type: ChannelType::Direct,
            members,
            created_at: now,
            last_activity: now,
            unread_count: 0,
            encrypted: true,
            pqc_enabled: true,
            on_chain: false,
        }
    }

    /// Create a group channel
    pub fn group(name: impl Into<String>, creator_fingerprint: &str) -> Self {
        let now = Self::now();

        let mut members = HashMap::new();
        members.insert(
            creator_fingerprint.to_string(),
            ChannelMember {
                fingerprint: creator_fingerprint.to_string(),
                name: None,
                is_admin: true,
                can_post: true,
                joined_at: now,
            },
        );

        Self {
            id: Self::generate_id(),
            name: name.into(),
            channel_type: ChannelType::Group,
            members,
            created_at: now,
            last_activity: now,
            unread_count: 0,
            encrypted: true,
            pqc_enabled: true,
            on_chain: false,
        }
    }

    /// Create an on-chain forum channel
    pub fn forum(name: impl Into<String>) -> Self {
        let name = name.into();
        let now = Self::now();

        Self {
            id: name.clone(),
            name,
            channel_type: ChannelType::Forum,
            members: HashMap::new(), // Open to all
            created_at: now,
            last_activity: now,
            unread_count: 0,
            encrypted: false, // Public forum
            pqc_enabled: false,
            on_chain: true,
        }
    }

    /// Add a member to the channel
    pub fn add_member(&mut self, fingerprint: &str, is_admin: bool) -> Result<()> {
        if self.channel_type == ChannelType::Direct {
            return Err(Error::Config("Cannot add members to DM".into()));
        }

        if self.members.contains_key(fingerprint) {
            return Err(Error::Config("Member already exists".into()));
        }

        self.members.insert(
            fingerprint.to_string(),
            ChannelMember {
                fingerprint: fingerprint.to_string(),
                name: None,
                is_admin,
                can_post: true,
                joined_at: Self::now(),
            },
        );

        Ok(())
    }

    /// Remove a member from the channel
    pub fn remove_member(&mut self, fingerprint: &str) -> Result<()> {
        if self.channel_type == ChannelType::Direct {
            return Err(Error::Config("Cannot remove members from DM".into()));
        }

        if self.members.remove(fingerprint).is_none() {
            return Err(Error::Config("Member not found".into()));
        }

        Ok(())
    }

    /// Check if fingerprint is a member
    pub fn is_member(&self, fingerprint: &str) -> bool {
        self.channel_type == ChannelType::Forum || self.members.contains_key(fingerprint)
    }

    /// Check if fingerprint is admin
    pub fn is_admin(&self, fingerprint: &str) -> bool {
        self.members
            .get(fingerprint)
            .map(|m| m.is_admin)
            .unwrap_or(false)
    }

    /// Update last activity
    pub fn touch(&mut self) {
        self.last_activity = Self::now();
    }

    /// Increment unread count
    pub fn increment_unread(&mut self) {
        self.unread_count += 1;
    }

    /// Mark as read
    pub fn mark_read(&mut self) {
        self.unread_count = 0;
    }

    /// Generate deterministic DM channel ID
    fn dm_id(a: &str, b: &str) -> String {
        let (first, second) = if a < b { (a, b) } else { (b, a) };
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(format!("dm:{}:{}", first, second));
        hex::encode(&hash[..16])
    }

    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..16)
            .map(|_| format!("{:02x}", rng.gen::<u8>()))
            .collect()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

/// Channel manager
pub struct ChannelManager {
    channels: HashMap<String, Channel>,
}

impl ChannelManager {
    /// Create a new channel manager
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
        }
    }

    /// Get or create a DM channel
    pub fn get_or_create_dm(&mut self, our_fp: &str, their_fp: &str) -> &mut Channel {
        let id = Channel::dm_id(our_fp, their_fp);

        self.channels
            .entry(id.clone())
            .or_insert_with(|| Channel::direct(our_fp, their_fp))
    }

    /// Create a new group channel
    pub fn create_group(&mut self, name: impl Into<String>, creator: &str) -> String {
        let channel = Channel::group(name, creator);
        let id = channel.id.clone();
        self.channels.insert(id.clone(), channel);
        id
    }

    /// Get a channel by ID
    pub fn get(&self, id: &str) -> Option<&Channel> {
        self.channels.get(id)
    }

    /// Get a mutable channel by ID
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Channel> {
        self.channels.get_mut(id)
    }

    /// List all channels
    pub fn list(&self) -> Vec<&Channel> {
        self.channels.values().collect()
    }

    /// List channels sorted by last activity
    pub fn list_by_activity(&self) -> Vec<&Channel> {
        let mut channels: Vec<_> = self.channels.values().collect();
        channels.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
        channels
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dm_channel() {
        let ch = Channel::direct("alice", "bob");
        assert_eq!(ch.channel_type, ChannelType::Direct);
        assert!(ch.is_member("alice"));
        assert!(ch.is_member("bob"));
        assert!(!ch.is_member("eve"));
    }

    #[test]
    fn test_dm_id_deterministic() {
        let id1 = Channel::dm_id("alice", "bob");
        let id2 = Channel::dm_id("bob", "alice");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_group_channel() {
        let mut ch = Channel::group("Team Chat", "alice");
        assert_eq!(ch.channel_type, ChannelType::Group);
        assert!(ch.is_admin("alice"));

        ch.add_member("bob", false).unwrap();
        assert!(ch.is_member("bob"));
        assert!(!ch.is_admin("bob"));
    }

    #[test]
    fn test_forum_channel() {
        let ch = Channel::forum("#quantum");
        assert_eq!(ch.channel_type, ChannelType::Forum);
        assert!(ch.on_chain);
        assert!(!ch.encrypted);
    }
}
