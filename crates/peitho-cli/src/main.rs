//! PeithoSecure CLI, Keystore Manager, and Developer Tools.

use std::io::Read;
use std::path::PathBuf;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use peitho_core::{generate_dsa_keypair, EncryptedKeystore};
use peitho_mcp::ProcessShield;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, decode_token, derive_root_ephemeral_key,
    encode_token, CapabilityToken, Caveat, CryptoProfile,
};

pub mod audit;
pub mod ui;

#[derive(Parser)]
#[command(name = "peitho")]
#[command(about = "PeithoSecure - Zero-Trust Cryptographic Authorization for AI Agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch the local developer dashboard and MCP proxy
    Dev {
        /// Port to bind the dashboard web server (default: 4040)
        #[arg(short, long, default_value_t = 4040)]
        port: u16,
    },
    /// Start the interactive developer dashboard
    Ui {
        /// Port to bind the dashboard web server (default: 4040)
        #[arg(short, long, default_value_t = 4040)]
        port: u16,
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
    /// Generate a new ML-DSA-44 post-quantum agent signing keypair
    Keygen {
        /// Optional file path to save the encrypted keystore
        #[arg(short, long)]
        save: Option<PathBuf>,
        /// Passphrase to encrypt the private key
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Inspect and decode a binary capability token
    Inspect {
        /// Hex token string, or path to token file
        #[arg(short, long)]
        token: Option<String>,
        /// Read token hex from standard input
        #[arg(long)]
        stdin: bool,
    },
    /// Capability token issuance and attenuation utilities
    Token {
        #[command(subcommand)]
        sub: TokenSubcommand,
    },
}

#[derive(Subcommand)]
enum TokenSubcommand {
    /// Issue a sample root capability token
    Issue {
        /// Token identifier
        #[arg(short, long, default_value = "tok_sample_root")]
        id: String,
        /// Resource prefix constraint
        #[arg(short, long, default_value = "s3://company/public/")]
        prefix: String,
    },
    /// Attenuate an existing capability token
    Attenuate {
        /// Parent token in hex
        #[arg(short, long)]
        parent_hex: String,
        /// Attenuated resource prefix
        #[arg(short, long)]
        prefix: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Dev { port } | Commands::Ui { port } => {
            println!("🚀 Starting Peitho Community Dashboard on http://127.0.0.1:{}", port);
            ui::start_ui_server(port).await?;
        }
        Commands::Keygen { save, password } => {
            let (pk, sk) = generate_dsa_keypair().context("failed to generate ML-DSA-44 keypair")?;
            println!("✅ Generated ML-DSA-44 Post-Quantum Keypair (FIPS 204)");
            if let Some(path) = save {
                let pass = match password {
                    Some(p) if !p.trim().is_empty() => p,
                    _ => bail!("Passphrase required. Provide --password <pass>"),
                };
                let keystore = EncryptedKeystore::encrypt(&pk, &sk, &pass)?;
                keystore.save_to_file(&path)?;
                println!("🔐 Encrypted Keystore saved to: {}", path.display());
            }
        }
        Commands::Wrap { target, token_file } => {
            let token = if let Some(path) = token_file {
                let bytes = std::fs::read(&path)?;
                Some(decode_token(&bytes)?)
            } else {
                None
            };
            let shield = ProcessShield::new(None);
            let exit_code = shield.run_shielded_process(&target, token).await?;
            std::process::exit(exit_code);
        }
        Commands::Inspect { token, stdin } => {
            let raw = if stdin {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else if let Some(s) = token {
                if let Ok(content) = std::fs::read_to_string(&s) { content } else { s }
            } else {
                bail!("Provide a token hex string via --token or --stdin");
            };
            let bytes = hex::decode(raw.trim()).context("invalid hex token")?;
            let decoded = decode_token(&bytes).context("failed to decode token")?;
            println!("✅ Decoded Capability Token:");
            println!("   • Token ID:           {}", decoded.token_id);
            println!("   • Crypto Profile:     {:?}", decoded.profile);
            println!("   • Delegation Depth:   {}", decoded.delegation_depth());
            println!("   • Root Caveats:       {:?}", decoded.root_caveats);
        }
        Commands::Token { sub } => match sub {
            TokenSubcommand::Issue { id, prefix } => {
                let (pk, sk) = generate_dsa_keypair()?;
                let caveats = vec![
                    Caveat::AllowedTools(vec!["search_documents".into(), "read_report".into()]),
                    Caveat::ResourcePrefix(prefix),
                    Caveat::ExpiresAt(2_000_000_000),
                ];
                let digest = compute_root_commitment(&id, CryptoProfile::SwarmSpeed, &caveats)?;
                let sig = peitho_core::sign_message(&sk, &digest)?;
                let token = CapabilityToken {
                    token_id: id,
                    profile: CryptoProfile::SwarmSpeed,
                    root_issuer_pk: pk,
                    root_caveats: caveats,
                    root_signature: sig,
                    delegations: vec![],
                };
                let bytes = encode_token(&token)?;
                println!("✅ Issued Root Capability Token:");
                println!("{}", hex::encode(bytes));
            }
            TokenSubcommand::Attenuate { parent_hex, prefix } => {
                let bytes = hex::decode(parent_hex.trim())?;
                let mut token = decode_token(&bytes)?;
                let root_key = derive_root_ephemeral_key(&token.root_signature);
                attenuate_hmac(&mut token, &root_key, vec![
                    Caveat::ResourcePrefix(prefix),
                    Caveat::ReadOnly,
                ])?;
                let enc = encode_token(&token)?;
                println!("✅ Attenuated Child Capability Token:");
                println!("{}", hex::encode(enc));
            }
        },
    }
    Ok(())
}
