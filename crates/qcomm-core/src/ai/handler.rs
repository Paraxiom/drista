//! Message Handler Framework

use super::agent::{AIAgent, AgentContext};
use crate::protocol::{Message, MessageType, Channel};
use crate::{Error, Result};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Context for message handlers
#[derive(Debug, Clone)]
pub struct HandlerContext {
    /// Current channel
    pub channel: Option<Channel>,
    /// Is the message a direct message
    pub is_dm: bool,
    /// Recent messages in conversation
    pub recent_messages: Vec<Message>,
    /// Users mentioned in the message
    pub mentions: Vec<String>,
}

impl HandlerContext {
    /// Create from message
    pub fn from_message(msg: &Message, channel: Option<Channel>) -> Self {
        let is_dm = channel
            .as_ref()
            .map(|c| c.channel_type == crate::protocol::ChannelType::Direct)
            .unwrap_or(true);

        Self {
            channel,
            is_dm,
            recent_messages: Vec::new(),
            mentions: msg.metadata.mentions.clone(),
        }
    }
}

/// Message handler result
#[derive(Debug)]
pub enum HandlerResult {
    /// Message was handled, don't process further
    Handled(Option<Message>),
    /// Message was not handled, continue to next handler
    NotHandled,
    /// Error occurred
    Error(Error),
}

/// Trait for message handlers
#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync {
    /// Handle an incoming message
    async fn handle(&self, msg: &Message, ctx: &HandlerContext) -> HandlerResult;

    /// Get handler name for logging
    fn name(&self) -> &str;

    /// Get handler priority (higher = runs first)
    fn priority(&self) -> i32 {
        0
    }
}

/// AI agent handler
pub struct AIAgentHandler {
    agent: Arc<AIAgent>,
}

impl AIAgentHandler {
    /// Create a new AI agent handler
    pub fn new(agent: Arc<AIAgent>) -> Self {
        Self { agent }
    }
}

#[async_trait::async_trait]
impl MessageHandler for AIAgentHandler {
    async fn handle(&self, msg: &Message, ctx: &HandlerContext) -> HandlerResult {
        let agent_ctx = AgentContext {
            channel: ctx.channel.clone(),
            recent_messages: ctx.recent_messages.clone(),
            mentions: ctx.mentions.clone(),
            is_dm: ctx.is_dm,
        };

        match self.agent.process_message(msg, agent_ctx).await {
            Ok(Some(response)) => HandlerResult::Handled(Some(response)),
            Ok(None) => HandlerResult::NotHandled,
            Err(e) => HandlerResult::Error(e),
        }
    }

    fn name(&self) -> &str {
        self.agent.name()
    }

    fn priority(&self) -> i32 {
        -10 // Run after other handlers
    }
}

/// Command handler for bot commands
pub struct CommandHandler {
    prefix: String,
    agent: Arc<AIAgent>,
}

impl CommandHandler {
    /// Create a new command handler
    pub fn new(prefix: impl Into<String>, agent: Arc<AIAgent>) -> Self {
        Self {
            prefix: prefix.into(),
            agent,
        }
    }

    /// Parse command from message
    fn parse_command(&self, text: &str) -> Option<(String, Vec<String>)> {
        if !text.starts_with(&self.prefix) {
            return None;
        }

        let without_prefix = &text[self.prefix.len()..];
        let parts: Vec<&str> = without_prefix.split_whitespace().collect();

        if parts.is_empty() {
            return None;
        }

        let command = parts[0].to_lowercase();
        let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

        Some((command, args))
    }
}

#[async_trait::async_trait]
impl MessageHandler for CommandHandler {
    async fn handle(&self, msg: &Message, _ctx: &HandlerContext) -> HandlerResult {
        // Only handle text messages
        let text = match &msg.content {
            crate::protocol::message::MessageContent::Text(t) => t,
            _ => return HandlerResult::NotHandled,
        };

        // Check for command
        let (command, args) = match self.parse_command(text) {
            Some(cmd) => cmd,
            None => return HandlerResult::NotHandled,
        };

        // Handle command
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match self.agent.handle_command(&command, &args_refs).await {
            Ok(response) => {
                let reply = Message::text(
                    &self.agent.fingerprint().to_hex(),
                    &msg.sender,
                    response,
                );
                HandlerResult::Handled(Some(reply))
            }
            Err(e) => HandlerResult::Error(e),
        }
    }

    fn name(&self) -> &str {
        "CommandHandler"
    }

    fn priority(&self) -> i32 {
        100 // Run before other handlers
    }
}

/// Message handler chain
pub struct HandlerChain {
    handlers: Vec<Box<dyn MessageHandler>>,
}

impl HandlerChain {
    /// Create a new handler chain
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Add a handler
    pub fn add<H: MessageHandler + 'static>(&mut self, handler: H) {
        self.handlers.push(Box::new(handler));
        // Sort by priority (descending)
        self.handlers.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    /// Process a message through the chain
    pub async fn process(&self, msg: &Message, ctx: &HandlerContext) -> Option<Message> {
        for handler in &self.handlers {
            match handler.handle(msg, ctx).await {
                HandlerResult::Handled(response) => {
                    tracing::debug!("Message handled by {}", handler.name());
                    return response;
                }
                HandlerResult::NotHandled => continue,
                HandlerResult::Error(e) => {
                    tracing::error!("Handler {} error: {}", handler.name(), e);
                    continue;
                }
            }
        }

        None
    }
}

impl Default for HandlerChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_parsing() {
        let agent = Arc::new(AIAgent::new(Default::default()).unwrap());
        let handler = CommandHandler::new("/", agent);

        let (cmd, args) = handler.parse_command("/help").unwrap();
        assert_eq!(cmd, "help");
        assert!(args.is_empty());

        let (cmd, args) = handler.parse_command("/status arg1 arg2").unwrap();
        assert_eq!(cmd, "status");
        assert_eq!(args, vec!["arg1", "arg2"]);

        assert!(handler.parse_command("no prefix").is_none());
    }
}
