/**
 * ChatView - Messages display + input component
 */

import { useEffect, useRef } from 'preact/hooks';
import { isWasmReady, getWasm } from '../lib/wasm.js';
import * as store from './store.js';

export function ChatView({ identity, starkIdentity, wasmLoaded }) {
  const channel = store.currentChannel.value;
  const msgs = store.currentMessages.value;
  const messagesRef = useRef(null);
  const inputRef = useRef(null);

  // Auto-scroll on new messages
  useEffect(() => {
    if (messagesRef.current) {
      messagesRef.current.scrollTop = messagesRef.current.scrollHeight;
    }
  }, [msgs.length]);

  // Focus input when channel changes
  useEffect(() => {
    if (channel && inputRef.current) {
      inputRef.current.focus();
    }
  }, [channel?.id]);

  async function sendMessage() {
    if (!channel) return;
    const text = inputRef.current?.value?.trim();
    if (!text) return;

    const message = {
      id: crypto.randomUUID(),
      sender: identity?.publicKey || 'local',
      recipient: channel.nostrPubkey || channel.id,
      text,
      timestamp: Date.now(),
      encrypted: channel.encrypted,
    };

    // Use WASM CSPRNG for message ID if available
    if (wasmLoaded) {
      try {
        const wasm = getWasm();
        const randomBytes = wasm.get_random_bytes(16);
        message.id = Array.from(randomBytes, b => b.toString(16).padStart(2, '0')).join('');
      } catch { /* fallback to crypto.randomUUID */ }
    }

    inputRef.current.value = '';
    inputRef.current.focus();

    await store.addMessage(channel.id, message);
  }

  function onKeyPress(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  // Channel header info
  let chatName = 'Select a channel';
  let chatStatus = '';
  if (channel) {
    chatName = channel.name;
    if (channel.channelType === 'direct') {
      chatStatus = channel.encrypted ? 'ENCRYPTED DM' : 'DIRECT MESSAGE';
    } else if (channel.channelType === 'forum') {
      chatStatus = 'PUBLIC CHANNEL';
    } else {
      chatStatus = channel.encrypted ? 'ENCRYPTED' : 'UNENCRYPTED';
    }
  }

  const myPubkey = identity?.publicKey;
  const myStarkPubkey = starkIdentity?.pubkeyHex;

  return (
    <section class="lcars-chat">
      <div class="lcars-chat-header">
        <span class="lcars-chat-name">{chatName}</span>
        <span class="lcars-chat-status">{chatStatus}</span>
      </div>

      <div class="lcars-chat-messages" ref={messagesRef}>
        {!channel && (
          <div class="welcome-panel">
            <h2>Welcome to Drista</h2>
            <p class="subtitle">Post-quantum secure messaging for Paraxiom collaborators</p>

            <div class="welcome-section">
              <h3>What is Drista?</h3>
              <p>Drista is a decentralized communication app built on the QuantumHarmony blockchain. Your messages are end-to-end encrypted and authenticated with zero-knowledge proofs.</p>
            </div>

            <div class="welcome-section">
              <h3>Getting Started</h3>
              <ol>
                <li><strong>Your identity is ready</strong> — A cryptographic keypair was generated for you automatically.</li>
                <li><strong>Select #drista channel</strong> — Click on the channel in the left panel to join the public forum.</li>
                <li><strong>Start a DM</strong> — Click any username to start an encrypted direct message.</li>
              </ol>
            </div>

            <div class="welcome-section">
              <h3>Security Features</h3>
              <ul>
                <li><strong>STARK Proofs</strong> — Messages are signed with zero-knowledge proofs</li>
                <li><strong>E2E Encryption</strong> — DMs use NIP-04 encryption (ECDH + AES-256)</li>
                <li><strong>Post-Quantum Ready</strong> — ML-KEM-1024 + Falcon-512 when WASM loads</li>
                <li><strong>Decentralized</strong> — Stored on QuantumHarmony validator nodes</li>
              </ul>
            </div>

            <div class="welcome-section status-section">
              <h3>Connection Status</h3>
              <p>Status indicator in the header shows: <strong>CONNECTED</strong> (all relays), <strong>PARTIAL</strong> (some relays), or <strong>OFFLINE</strong></p>
            </div>
          </div>
        )}
        {channel && msgs.length === 0 && (
          <div class="no-messages">
            <p>No messages yet</p>
            <p class="hint">Start the conversation...</p>
          </div>
        )}
        {channel && msgs.map(msg => (
          <Message
            key={msg.id}
            msg={msg}
            isOutgoing={msg.sender === myPubkey || msg.starkPubkey === myStarkPubkey}
          />
        ))}
      </div>

      <div class="lcars-chat-input">
        <input
          type="text"
          ref={inputRef}
          placeholder="Type a message..."
          disabled={!channel}
          onKeyPress={onKeyPress}
        />
        <button class="lcars-button" disabled={!channel} onClick={sendMessage}>
          SEND
        </button>
      </div>
    </section>
  );
}

function Message({ msg, isOutgoing }) {
  const time = new Date(msg.timestamp).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });

  const senderDisplay = isOutgoing ? 'You' : (msg.sender?.slice(0, 8) + '...');

  return (
    <div class={`message ${isOutgoing ? 'outgoing' : 'incoming'}`}>
      {!isOutgoing && <span class="message-sender">{senderDisplay}</span>}
      <div class="message-content">{escapeHtml(msg.text)}</div>
      <span class="message-time">
        {time}
        {msg.starkProof && msg.starkVerified === true && (
          <span class="message-badge stark verified">STARK ✓</span>
        )}
        {msg.starkProof && msg.starkVerified === false && (
          <span class="message-badge stark failed">STARK ✗</span>
        )}
        {msg.starkProof && msg.starkVerified == null && (
          <span class="message-badge stark">STARK</span>
        )}
        {(msg.sentViaNostr || msg.fromNostr) && (
          <span class="message-badge nostr">NOSTR</span>
        )}
        {msg.encrypted && (
          <span class="message-badge encrypted">ENC</span>
        )}
      </span>
    </div>
  );
}

function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
