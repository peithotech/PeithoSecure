//! PeithoSecure CLI, Keystore Manager, and Process Shield.

use std::path::PathBuf;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use peitho_core::{generate_dsa_keypair, EncryptedKeystore};
use peitho_mcp::ProcessShield;
use peitho_token::decode_token;
use tracing::info;

pub mod audit;
pub mod ui;

use audit::{AuditEventType, AuditRecord};

#[derive(Parser)]
#[command(name = "peitho")]
#[command(about = "PeithoSecure - Production Post-Quantum Zero-Trust Framework for AI Agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ML-DSA-44 post-quantum agent signing keypair
    Keygen {
        /// Optional file path to save the encrypted keystore
        #[arg(short, long)]
        save: Option<PathBuf>,
        /// Passphrase to encrypt the private key with AES-256-GCM + Argon2id
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Wrap and protect a real MCP server process over live OS stdio
    Wrap {
        /// The target child command to spawn and shield
        #[arg(short, long)]
        target: String,
        /// Optional path to a capability token file to enforce
        #[arg(short, long)]
        token_file: Option<PathBuf>,
    },
    /// Inspect and decode a binary capability token
    Inspect {
        /// Hex or base64 token string
        token: String,
    },
    /// Start the local interactive developer dashboard
    Ui {
        /// Port to bind the dashboard web server (default: 8080)
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { save, password } => {
            let (pk, sk) = generate_dsa_keypair().context("failed to generate ML-DSA-44 keypair")?;
            info!("Generated NIST FIPS 204 ML-DSA-44 keypair!");
            println!("✅ Generated ML-DSA-44 Post-Quantum Keypair");
            println!("   • Public Key Size:  {} bytes", pk.as_bytes().len());
            println!("   • Secret Key Size:  {} bytes", sk.as_bytes().len());

            if let Some(path) = save {
                let pass = match password {
                    Some(p) if !p.trim().is_empty() => p,
                    _ => bail!("Passphrase required to encrypt keystore. Provide --password <pass>"),
                };
                let keystore = EncryptedKeystore::encrypt(&pk, &sk, &pass)
                    .context("failed to encrypt keystore with AES-256-GCM + Argon2id")?;
                keystore.save_to_file(&path)
                    .context("failed to write encrypted keystore to disk")?;
                println!("🔐 Encrypted Keystore saved to: {} (mode 0600)", path.display());
            }
        }
        Commands::Wrap { target, token_file } => {
            let token = if let Some(path) = token_file {
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("failed to read token file: {}", path.display()))?;
                Some(decode_token(&bytes).context("failed to decode capability token")?)
            } else {
                None
            };

            let shield = ProcessShield::new(None);
            let exit_code = shield.run_shielded_process(&target, token).await
                .context("MCP process shield failed")?;
            std::process::exit(exit_code);
        }
        Commands::Inspect { token } => {
            let bytes = hex::decode(token.trim()).context("invalid hex string")?;
            let decoded = decode_token(&bytes).context("failed to decode capability token")?;
            let audit = AuditRecord::new(
                AuditEventType::TokenIssued,
                &decoded.token_id,
                None,
                "INSPECTED",
                0.0,
                Some(format!("Profile: {:?}", decoded.profile)),
            );
            info!(target: "audit", ndjson = %audit.to_ndjson());
            println!("✅ Decoded Capability Token:");
            println!("   • Token ID:           {}", decoded.token_id);
            println!("   • Crypto Profile:     {:?}", decoded.profile);
            println!("   • Delegation Depth:   {}", decoded.delegation_depth());
            println!("   • Root Caveats Count: {}", decoded.root_caveats.len());
        }
        Commands::Ui { port } => {
            ui::start_ui_server(port).await?;
        }
    }

    Ok(())
}
