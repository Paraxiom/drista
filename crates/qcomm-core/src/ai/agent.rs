//! AI Agent Implementation

use super::{AIMessage, AIProviderTrait, CompletionRequest, ModelConfig};
use crate::protocol::{Message, MessageType, Channel, ChannelType};
use crate::{Error, Result, Identity, Fingerprint};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Agent capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentCapability {
    /// Respond to direct messages
    DirectMessage,
    /// Respond to mentions in channels
    Mentions,
    /// Participate in specific channels
    ChannelParticipation,
    /// Execute commands
    Commands,
    /// Query blockchain state
    BlockchainQuery,
    /// Post to forums
    ForumPost,
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Agent ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Model configuration
    pub model: ModelConfig,
    /// Enabled capabilities
    pub capabilities: HashSet<AgentCapability>,
    /// Channels to join
    pub channels: Vec<String>,
    /// Response prefix
    pub response_prefix: Option<String>,
    /// Max context messages
    pub max_context: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            id: "default-agent".to_string(),
            name: "QComm Assistant".to_string(),
            model: ModelConfig::default(),
            capabilities: [
                AgentCapability::DirectMessage,
                AgentCapability::Mentions,
            ]
            .into_iter()
            .collect(),
            channels: vec!["#quantum".to_string()],
            response_prefix: None,
            max_context: 10,
        }
    }
}

/// Context for agent responses
#[derive(Debug, Clone)]
pub struct AgentContext {
    /// Channel info
    pub channel: Option<Channel>,
    /// Recent messages
    pub recent_messages: Vec<Message>,
    /// Mentioned users
    pub mentions: Vec<String>,
    /// Is direct message
    pub is_dm: bool,
}

/// AI Agent
pub struct AIAgent {
    /// Configuration
    config: AgentConfig,
    /// Agent identity
    identity: Identity,
    /// AI provider
    provider: Option<Arc<dyn AIProviderTrait>>,
    /// Joined channels
    joined_channels: Arc<Mutex<HashSet<String>>>,
    /// Message history per channel
    history: Arc<Mutex<HashMap<String, Vec<AIMessage>>>>,
}

impl AIAgent {
    /// Create a new AI agent
    pub fn new(config: AgentConfig) -> Result<Self> {
        let identity = Identity::generate()?;

        Ok(Self {
            config,
            identity,
            provider: None,
            joined_channels: Arc::new(Mutex::new(HashSet::new())),
            history: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Create with existing identity
    pub fn with_identity(config: AgentConfig, identity: Identity) -> Self {
        Self {
            config,
            identity,
            provider: None,
            joined_channels: Arc::new(Mutex::new(HashSet::new())),
            history: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the AI provider
    pub fn set_provider(&mut self, provider: Arc<dyn AIProviderTrait>) {
        self.provider = Some(provider);
    }

    /// Get agent ID
    pub fn id(&self) -> &str {
        &self.config.id
    }

    /// Get agent name
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get agent fingerprint
    pub fn fingerprint(&self) -> &Fingerprint {
        self.identity.fingerprint()
    }

    /// Check if agent has a capability
    pub fn has_capability(&self, cap: AgentCapability) -> bool {
        self.config.capabilities.contains(&cap)
    }

    /// Join a channel
    pub async fn join_channel(&self, channel: &str) {
        self.joined_channels.lock().await.insert(channel.to_string());
        tracing::info!("Agent {} joined channel {}", self.config.name, channel);
    }

    /// Leave a channel
    pub async fn leave_channel(&self, channel: &str) {
        self.joined_channels.lock().await.remove(channel);
        tracing::info!("Agent {} left channel {}", self.config.name, channel);
    }

    /// Check if agent is in channel
    pub async fn is_in_channel(&self, channel: &str) -> bool {
        self.joined_channels.lock().await.contains(channel)
    }

    /// Process an incoming message
    pub async fn process_message(&self, msg: &Message, context: AgentContext) -> Result<Option<Message>> {
        // Check if we should respond
        let should_respond = self.should_respond(msg, &context);

        if !should_respond {
            return Ok(None);
        }

        // Build context messages
        let messages = self.build_context(msg, &context).await;

        // Generate response
        let response_text = self.generate_response(messages).await?;

        // Create response message
        let mut response = Message::text(
            &self.identity.fingerprint().to_hex(),
            &msg.sender,
            response_text,
        );

        response.metadata.agent_id = Some(self.config.id.clone());
        response.reply_to = Some(msg.id.clone());

        Ok(Some(response))
    }

    /// Check if agent should respond to message
    fn should_respond(&self, msg: &Message, context: &AgentContext) -> bool {
        // Don't respond to own messages
        if msg.sender == self.identity.fingerprint().to_hex() {
            return false;
        }

        // DM capability check
        if context.is_dm && !self.has_capability(AgentCapability::DirectMessage) {
            return false;
        }

        // Mention check for channels
        if !context.is_dm {
            if !self.has_capability(AgentCapability::Mentions) {
                return false;
            }

            // Must be mentioned
            let our_fp = self.identity.fingerprint().to_hex();
            if !context.mentions.contains(&our_fp) && !context.mentions.contains(&self.config.name) {
                return false;
            }
        }

        true
    }

    /// Build context messages for AI
    async fn build_context(&self, msg: &Message, context: &AgentContext) -> Vec<AIMessage> {
        let mut messages = Vec::new();

        // System prompt
        let system_prompt = self.config.model.system_prompt.clone().unwrap_or_else(|| {
            format!(
                "You are {}, an AI assistant in the Quantum Communicator chat app. \
                 You help users with questions about the app, blockchain, and general topics. \
                 Keep responses concise and helpful.",
                self.config.name
            )
        });
        messages.push(AIMessage::system(system_prompt));

        // Add channel history
        let channel_id = if context.is_dm {
            &msg.sender
        } else {
            context.channel.as_ref().map(|c| c.id.as_str()).unwrap_or("unknown")
        };

        let history = self.history.lock().await;
        if let Some(channel_history) = history.get(channel_id) {
            let start = channel_history.len().saturating_sub(self.config.max_context);
            messages.extend(channel_history[start..].to_vec());
        }

        // Add current message
        if let MessageType::Text = msg.msg_type {
            if let crate::protocol::message::MessageContent::Text(text) = &msg.content {
                messages.push(AIMessage::user(format!("{}: {}", msg.sender, text)));
            }
        }

        messages
    }

    /// Generate response using AI provider
    async fn generate_response(&self, messages: Vec<AIMessage>) -> Result<String> {
        let provider = self.provider.as_ref().ok_or_else(|| {
            Error::AiAgent("No AI provider configured".to_string())
        })?;

        let request = CompletionRequest {
            messages,
            config: self.config.model.clone(),
        };

        let response = provider.complete(request).await?;

        // Add prefix if configured
        let text = if let Some(prefix) = &self.config.response_prefix {
            format!("{} {}", prefix, response.content)
        } else {
            response.content
        };

        Ok(text)
    }

    /// Handle a command
    pub async fn handle_command(&self, command: &str, args: &[&str]) -> Result<String> {
        if !self.has_capability(AgentCapability::Commands) {
            return Err(Error::AiAgent("Commands not enabled".to_string()));
        }

        match command {
            "help" => Ok(self.help_text()),
            "status" => Ok(self.status_text().await),
            "channels" => Ok(self.channels_text().await),
            _ => Ok(format!("Unknown command: {}", command)),
        }
    }

    fn help_text(&self) -> String {
        format!(
            "**{}** - AI Assistant\n\n\
             Available commands:\n\
             - `/help` - Show this help\n\
             - `/status` - Show agent status\n\
             - `/channels` - List joined channels\n\n\
             Mention me in a channel or send a DM to chat.",
            self.config.name
        )
    }

    async fn status_text(&self) -> String {
        let channels = self.joined_channels.lock().await;
        format!(
            "Agent: {}\n\
             ID: {}\n\
             Fingerprint: {}\n\
             Channels: {}\n\
             Capabilities: {:?}",
            self.config.name,
            self.config.id,
            self.identity.fingerprint(),
            channels.len(),
            self.config.capabilities
        )
    }

    async fn channels_text(&self) -> String {
        let channels = self.joined_channels.lock().await;
        if channels.is_empty() {
            "Not in any channels".to_string()
        } else {
            channels.iter().cloned().collect::<Vec<_>>().join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_creation() {
        let config = AgentConfig::default();
        let agent = AIAgent::new(config).unwrap();

        assert!(agent.has_capability(AgentCapability::DirectMessage));
        assert!(agent.has_capability(AgentCapability::Mentions));
    }

    #[tokio::test]
    async fn test_join_channel() {
        let agent = AIAgent::new(AgentConfig::default()).unwrap();

        agent.join_channel("#test").await;
        assert!(agent.is_in_channel("#test").await);

        agent.leave_channel("#test").await;
        assert!(!agent.is_in_channel("#test").await);
    }
}
