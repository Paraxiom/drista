//! Drista CLI - Post-quantum secure messaging client
//!
//! Usage:
//!   drista alice         # Run as Alice (interactive mode)
//!   drista bob           # Run as Bob
//!   drista send-pq       # Send post-quantum encrypted DM
//!   drista pq-keygen     # Generate PQ keypair and show public key

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use rustyline::DefaultEditor;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, warn};

mod crypto;
mod nostr;
mod pq_dm;

use nostr::{NostrClient, NostrEvent, KIND_ENCRYPTED_DM, KIND_PQ_ENCRYPTED_DM};
use pq_dm::PqSessionManager;

/// Drista - Post-quantum secure messaging
#[derive(Parser)]
#[command(name = "drista")]
#[command(about = "Post-quantum secure messaging CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Nostr relay URL
    #[arg(short, long, default_value = "wss://relay.damus.io")]
    relay: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as Alice (test identity 1)
    Alice,
    /// Run as Bob (test identity 2)
    Bob,
    /// Run with custom identity
    Run {
        /// Private key (hex)
        #[arg(short, long)]
        privkey: Option<String>,
        /// Display name
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Generate a new Nostr keypair
    Keygen,
    /// Generate a new PQ (ML-KEM-1024) keypair
    PqKeygen,
    /// Send a NIP-04 encrypted DM (classical crypto)
    Send {
        /// Recipient public key (hex)
        #[arg(short, long)]
        to: String,
        /// Message text
        message: String,
        /// Sender private key (hex)
        #[arg(short, long)]
        privkey: String,
    },
    /// Send a PQ-encrypted DM (ML-KEM-1024 + AES-256-GCM)
    SendPq {
        /// Recipient Nostr public key (hex)
        #[arg(short, long)]
        to: String,
        /// Recipient's PQ public key (base64)
        #[arg(long)]
        to_pq: String,
        /// Message text
        message: String,
        /// Sender private key (hex)
        #[arg(short, long)]
        privkey: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Alice => {
            run_interactive("Alice", &cli.relay, None).await?;
        }
        Commands::Bob => {
            run_interactive("Bob", &cli.relay, None).await?;
        }
        Commands::Run { privkey, name } => {
            let display_name = name.unwrap_or_else(|| "User".to_string());
            run_interactive(&display_name, &cli.relay, privkey).await?;
        }
        Commands::Keygen => {
            let (sk, pk) = generate_keypair();
            println!("{}", "Generated Nostr keypair:".green().bold());
            println!("  Private key: {}", sk.red());
            println!("  Public key:  {}", pk.cyan());
        }
        Commands::PqKeygen => {
            let pq_manager = PqSessionManager::new()?;
            let pq_pubkey = pq_manager.public_key_base64();
            println!("{}", "Generated ML-KEM-1024 keypair:".green().bold());
            println!("  PQ Public key (base64):");
            println!("  {}", pq_pubkey.cyan());
            println!();
            println!("{}", "Share this with your contacts for PQ-encrypted DMs.".yellow());
        }
        Commands::Send {
            to,
            message,
            privkey,
        } => {
            send_dm(&cli.relay, &privkey, &to, &message).await?;
        }
        Commands::SendPq {
            to,
            to_pq,
            message,
            privkey,
        } => {
            send_pq_dm(&cli.relay, &privkey, &to, &to_pq, &message).await?;
        }
    }

    Ok(())
}

fn generate_keypair() -> (String, String) {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (secret_key, _public_key) = secp.generate_keypair(&mut rng);
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _parity) = keypair.x_only_public_key();

    (
        hex::encode(secret_key.secret_bytes()),
        hex::encode(xonly.serialize()),
    )
}

async fn run_interactive(name: &str, relay_url: &str, privkey: Option<String>) -> Result<()> {
    // Generate or use provided keypair
    let (sk_hex, pk_hex) = match privkey {
        Some(sk) => {
            let secp = Secp256k1::new();
            let secret_key = SecretKey::from_slice(&hex::decode(&sk)?)?;
            let keypair = Keypair::from_secret_key(&secp, &secret_key);
            let (xonly, _) = keypair.x_only_public_key();
            (sk, hex::encode(xonly.serialize()))
        }
        None => {
            // Generate deterministic keys for Alice/Bob for testing
            let seed = format!("drista-test-{}", name.to_lowercase());
            let hash = Sha256::digest(seed.as_bytes());
            let secp = Secp256k1::new();
            let secret_key = SecretKey::from_slice(&hash)?;
            let keypair = Keypair::from_secret_key(&secp, &secret_key);
            let (xonly, _) = keypair.x_only_public_key();
            (
                hex::encode(secret_key.secret_bytes()),
                hex::encode(xonly.serialize()),
            )
        }
    };

    // Initialize PQ session manager
    let pq_manager = PqSessionManager::new()?;
    let pq_pubkey = pq_manager.public_key_base64();

    println!(
        "{}",
        format!("=== Drista CLI ({}) ===", name).green().bold()
    );
    println!("Nostr pubkey: {}", pk_hex.cyan());
    println!("PQ pubkey:    {}...", &pq_pubkey[..40].cyan());
    println!("Relay:        {}", relay_url.yellow());
    println!();
    println!("Commands:");
    println!("  /dm <pubkey> <message>           - Send NIP-04 DM (classical)");
    println!("  /pqdm <pubkey> <pq_pubkey> <msg> - Send PQ-DM (ML-KEM-1024)");
    println!("  /pubkey                          - Show your public keys");
    println!("  /quit                            - Exit");
    println!();

    // Create Nostr client
    let mut client = NostrClient::new(&sk_hex, relay_url).await?;

    // Subscribe to our DMs
    client.subscribe_dms().await?;

    // Channel for incoming messages
    let (msg_tx, mut msg_rx) = mpsc::channel::<NostrEvent>(100);

    // Spawn message receiver task
    let client = Arc::new(Mutex::new(client));
    let client_recv = client.clone();
    let pq_manager = Arc::new(pq_manager);
    let pq_manager_recv = pq_manager.clone();

    tokio::spawn(async move {
        loop {
            let event = {
                let mut c = client_recv.lock().await;
                c.receive().await
            };

            match event {
                Ok(Some(ev)) => {
                    if msg_tx.send(ev).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
                Err(e) => {
                    error!("Receive error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    });

    // Interactive loop
    let mut rl = DefaultEditor::new()?;
    let prompt = format!("[{}] > ", name);

    loop {
        // Check for incoming messages (non-blocking)
        while let Ok(event) = msg_rx.try_recv() {
            let from = &event.pubkey[..16];

            if event.kind == KIND_ENCRYPTED_DM {
                // NIP-04 DM
                let decrypted = {
                    let c = client.lock().await;
                    c.decrypt_dm(&event)
                };

                match decrypted {
                    Ok(text) => {
                        println!(
                            "\n{} {}: {}",
                            "DM from".magenta(),
                            from.cyan(),
                            text.white()
                        );
                    }
                    Err(e) => {
                        warn!("Failed to decrypt NIP-04 DM: {}", e);
                    }
                }
            } else if event.kind == KIND_PQ_ENCRYPTED_DM {
                // PQ-DM
                match pq_manager_recv.decrypt(&event.pubkey, &event.content) {
                    Ok(text) => {
                        println!(
                            "\n{} {}: {}",
                            "PQ-DM from".bright_cyan().bold(),
                            from.cyan(),
                            text.white()
                        );
                    }
                    Err(e) => {
                        warn!("Failed to decrypt PQ-DM: {}", e);
                    }
                }
            }
        }

        // Read user input
        let line = match rl.readline(&prompt) {
            Ok(l) => l,
            Err(_) => break,
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let _ = rl.add_history_entry(line);

        if line.starts_with("/dm ") {
            let parts: Vec<&str> = line[4..].splitn(2, ' ').collect();
            if parts.len() < 2 {
                println!("{}", "Usage: /dm <pubkey> <message>".red());
                continue;
            }

            let to_pubkey = parts[0];
            let message = parts[1];

            let result = {
                let c = client.lock().await;
                c.send_dm(to_pubkey, message).await
            };

            match result {
                Ok(_) => println!("{}", "NIP-04 DM sent!".green()),
                Err(e) => println!("{}: {}", "Failed to send".red(), e),
            }
        } else if line.starts_with("/pqdm ") {
            let parts: Vec<&str> = line[6..].splitn(3, ' ').collect();
            if parts.len() < 3 {
                println!(
                    "{}",
                    "Usage: /pqdm <nostr_pubkey> <pq_pubkey_base64> <message>".red()
                );
                continue;
            }

            let to_nostr_pubkey = parts[0];
            let to_pq_pubkey = parts[1];
            let message = parts[2];

            // Register peer's PQ key and encrypt
            if let Err(e) = pq_manager.register_peer_key(to_nostr_pubkey, to_pq_pubkey) {
                println!("{}: {}", "Invalid PQ public key".red(), e);
                continue;
            }

            match pq_manager.encrypt(to_nostr_pubkey, message) {
                Ok(encrypted_content) => {
                    // Send as Kind 20004 event
                    let result = {
                        let c = client.lock().await;
                        c.send_pq_dm(to_nostr_pubkey, &encrypted_content, &pq_pubkey)
                            .await
                    };

                    match result {
                        Ok(_) => println!("{}", "PQ-DM sent! (ML-KEM-1024 + AES-256-GCM)".bright_cyan()),
                        Err(e) => println!("{}: {}", "Failed to send".red(), e),
                    }
                }
                Err(e) => println!("{}: {}", "Encryption failed".red(), e),
            }
        } else if line == "/pubkey" {
            println!("Nostr public key: {}", pk_hex.cyan());
            println!("PQ public key:    {}", pq_pubkey.cyan());
        } else if line == "/quit" || line == "/q" {
            break;
        } else {
            println!(
                "{}",
                "Unknown command. Try /dm, /pqdm, /pubkey, or /quit".yellow()
            );
        }
    }

    println!("Goodbye!");
    Ok(())
}

async fn send_dm(relay_url: &str, privkey: &str, to: &str, message: &str) -> Result<()> {
    let client = NostrClient::new(privkey, relay_url).await?;
    client.send_dm(to, message).await?;
    println!("{}", "NIP-04 DM sent successfully!".green());
    Ok(())
}

async fn send_pq_dm(
    relay_url: &str,
    privkey: &str,
    to_nostr: &str,
    to_pq: &str,
    message: &str,
) -> Result<()> {
    // Initialize PQ session manager
    let pq_manager = PqSessionManager::new()?;
    let our_pq_pubkey = pq_manager.public_key_base64();

    // Register recipient's PQ key
    pq_manager.register_peer_key(to_nostr, to_pq)?;

    // Encrypt message
    let encrypted_content = pq_manager.encrypt(to_nostr, message)?;

    // Create Nostr client and send
    let client = NostrClient::new(privkey, relay_url).await?;
    client
        .send_pq_dm(to_nostr, &encrypted_content, &our_pq_pubkey)
        .await?;

    println!("{}", "PQ-DM sent successfully!".bright_cyan().bold());
    println!(
        "{}",
        "  (ML-KEM-1024 + AES-256-GCM encryption)".bright_cyan()
    );
    Ok(())
}
