//! AI Agent Integration
//!
//! Framework for AI agents that can participate in channels,
//! respond to mentions, and provide automated assistance.

pub mod agent;
pub mod handler;

pub use agent::{AIAgent, AgentConfig, AgentCapability};
pub use handler::{MessageHandler, HandlerContext};

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// AI provider types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AIProvider {
    /// Claude by Anthropic
    Claude,
    /// OpenAI GPT
    OpenAI,
    /// Local LLM (llama.cpp, etc.)
    Local,
    /// Custom provider
    Custom,
}

/// AI model configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Provider
    pub provider: AIProvider,
    /// Model name/ID
    pub model: String,
    /// API endpoint (for custom providers)
    pub endpoint: Option<String>,
    /// API key (for cloud providers)
    #[serde(skip_serializing)]
    pub api_key: Option<String>,
    /// Temperature (0.0 - 1.0)
    pub temperature: f32,
    /// Max tokens to generate
    pub max_tokens: usize,
    /// System prompt
    pub system_prompt: Option<String>,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            provider: AIProvider::Claude,
            model: "claude-3-sonnet-20240229".to_string(),
            endpoint: None,
            api_key: None,
            temperature: 0.7,
            max_tokens: 1024,
            system_prompt: None,
        }
    }
}

/// Message for AI context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIMessage {
    /// Role (user, assistant, system)
    pub role: String,
    /// Content
    pub content: String,
}

impl AIMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
        }
    }
}

/// AI completion request
#[derive(Debug, Clone)]
pub struct CompletionRequest {
    /// Messages for context
    pub messages: Vec<AIMessage>,
    /// Model configuration
    pub config: ModelConfig,
}

/// AI completion response
#[derive(Debug, Clone)]
pub struct CompletionResponse {
    /// Generated content
    pub content: String,
    /// Tokens used
    pub tokens_used: usize,
    /// Finish reason
    pub finish_reason: String,
}

/// Trait for AI providers
#[async_trait::async_trait]
pub trait AIProviderTrait: Send + Sync {
    /// Complete a prompt
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;

    /// Stream a completion
    async fn stream_complete(
        &self,
        request: CompletionRequest,
        callback: Box<dyn Fn(&str) + Send>,
    ) -> Result<CompletionResponse>;
}
