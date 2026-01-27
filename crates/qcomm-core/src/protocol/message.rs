//! Message types and encoding

use crate::{Error, Result, Fingerprint};
use serde::{Deserialize, Serialize};

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Plain text message
    Text = 0,
    /// Binary data
    Binary = 1,
    /// File attachment reference
    File = 2,
    /// Reaction to another message
    Reaction = 3,
    /// Message edit
    Edit = 4,
    /// Message deletion
    Delete = 5,
    /// Typing indicator
    Typing = 6,
    /// Read receipt
    Read = 7,
    /// System message
    System = 8,
    /// AI agent message
    Agent = 9,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Text),
            1 => Ok(Self::Binary),
            2 => Ok(Self::File),
            3 => Ok(Self::Reaction),
            4 => Ok(Self::Edit),
            5 => Ok(Self::Delete),
            6 => Ok(Self::Typing),
            7 => Ok(Self::Read),
            8 => Ok(Self::System),
            9 => Ok(Self::Agent),
            _ => Err(Error::InvalidMessage(format!("Unknown message type: {}", value))),
        }
    }
}

/// A chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message ID
    pub id: String,
    /// Message type
    pub msg_type: MessageType,
    /// Sender fingerprint
    pub sender: String,
    /// Recipient or channel
    pub recipient: String,
    /// Timestamp (Unix ms)
    pub timestamp: u64,
    /// Message content
    pub content: MessageContent,
    /// Reply to message ID
    pub reply_to: Option<String>,
    /// Additional metadata
    pub metadata: MessageMetadata,
}

/// Message content variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum MessageContent {
    /// Text content
    Text(String),
    /// Binary content (base64 encoded in JSON)
    Binary(Vec<u8>),
    /// File reference
    File {
        name: String,
        size: u64,
        mime_type: String,
        hash: String,
    },
    /// Reaction emoji
    Reaction(String),
    /// Edit with new text
    Edit {
        message_id: String,
        new_text: String,
    },
    /// Delete reference
    Delete {
        message_id: String,
    },
    /// Empty (for typing/read)
    Empty,
}

/// Message metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageMetadata {
    /// Message was encrypted with PQC
    #[serde(default)]
    pub pqc_encrypted: bool,
    /// QRNG was used for keys
    #[serde(default)]
    pub qrng_entropy: bool,
    /// QKD enhanced
    #[serde(default)]
    pub qkd_enhanced: bool,
    /// AI agent ID if from agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Mentions in message
    #[serde(default)]
    pub mentions: Vec<String>,
    /// On-chain tx hash if persisted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

impl Message {
    /// Create a new text message
    pub fn text(sender: &str, recipient: &str, text: impl Into<String>) -> Self {
        Self {
            id: Self::generate_id(),
            msg_type: MessageType::Text,
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            timestamp: Self::now(),
            content: MessageContent::Text(text.into()),
            reply_to: None,
            metadata: MessageMetadata::default(),
        }
    }

    /// Create a binary message
    pub fn binary(sender: &str, recipient: &str, data: Vec<u8>) -> Self {
        Self {
            id: Self::generate_id(),
            msg_type: MessageType::Binary,
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            timestamp: Self::now(),
            content: MessageContent::Binary(data),
            reply_to: None,
            metadata: MessageMetadata::default(),
        }
    }

    /// Create a file message
    pub fn file(
        sender: &str,
        recipient: &str,
        name: String,
        size: u64,
        mime_type: String,
        hash: String,
    ) -> Self {
        Self {
            id: Self::generate_id(),
            msg_type: MessageType::File,
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            timestamp: Self::now(),
            content: MessageContent::File {
                name,
                size,
                mime_type,
                hash,
            },
            reply_to: None,
            metadata: MessageMetadata::default(),
        }
    }

    /// Create a reaction
    pub fn reaction(sender: &str, recipient: &str, emoji: impl Into<String>, reply_to: &str) -> Self {
        Self {
            id: Self::generate_id(),
            msg_type: MessageType::Reaction,
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            timestamp: Self::now(),
            content: MessageContent::Reaction(emoji.into()),
            reply_to: Some(reply_to.to_string()),
            metadata: MessageMetadata::default(),
        }
    }

    /// Create a typing indicator
    pub fn typing(sender: &str, recipient: &str) -> Self {
        Self {
            id: Self::generate_id(),
            msg_type: MessageType::Typing,
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            timestamp: Self::now(),
            content: MessageContent::Empty,
            reply_to: None,
            metadata: MessageMetadata::default(),
        }
    }

    /// Create a read receipt
    pub fn read(sender: &str, recipient: &str, last_read: &str) -> Self {
        Self {
            id: Self::generate_id(),
            msg_type: MessageType::Read,
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            timestamp: Self::now(),
            content: MessageContent::Empty,
            reply_to: Some(last_read.to_string()),
            metadata: MessageMetadata::default(),
        }
    }

    /// Set reply reference
    pub fn with_reply(mut self, reply_to: &str) -> Self {
        self.reply_to = Some(reply_to.to_string());
        self
    }

    /// Set PQC metadata
    pub fn with_pqc(mut self) -> Self {
        self.metadata.pqc_encrypted = true;
        self
    }

    /// Add mention
    pub fn with_mention(mut self, fingerprint: &str) -> Self {
        self.metadata.mentions.push(fingerprint.to_string());
        self
    }

    /// Encode to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| Error::Serialization(e.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_message() {
        let msg = Message::text("alice", "bob", "Hello!");
        assert_eq!(msg.msg_type, MessageType::Text);
        assert!(matches!(msg.content, MessageContent::Text(_)));
    }

    #[test]
    fn test_message_encoding() {
        let msg = Message::text("alice", "bob", "Test");
        let encoded = msg.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded.sender, "alice");
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::try_from(0).unwrap(), MessageType::Text);
        assert!(MessageType::try_from(255).is_err());
    }
}
