//! # Wallet CLI Commands
//!
//! Command-line interface for wallet operations.

use clap::Subcommand;
use crate::context::AppContext;
use crate::errors::Result;
use crate::services::wallet::WalletService;
use super::OutputFormat;
use std::path::Path;

/// Read coldkey address from coldkeypub.txt file
fn read_coldkey_address(wallet_path: &Path) -> String {
    let coldkeypub_path = wallet_path.join("coldkeypub.txt");
    if coldkeypub_path.exists() {
        match std::fs::read_to_string(&coldkeypub_path) {
            Ok(content) => {
                // Try to parse as JSON and extract ss58Address
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(addr) = json.get("ss58Address").and_then(|v| v.as_str()) {
                        return addr.to_string();
                    }
                }
                // Fallback: maybe it's just a plain address
                content.trim().to_string()
            }
            Err(_) => "N/A".to_string(),
        }
    } else {
        "N/A (coldkeypub.txt not found)".to_string()
    }
}

/// Wallet subcommands
#[derive(Subcommand, Debug)]
pub enum WalletCommand {
    /// Create a new wallet
    Create {
        /// Wallet name
        name: String,
        
        /// Number of mnemonic words (12 or 24)
        #[arg(short, long, default_value = "12")]
        words: u8,
        
        /// Skip password prompt (insecure)
        #[arg(long)]
        no_password: bool,
    },
    
    /// List all wallets
    List,
    
    /// Show wallet balance
    Balance {
        /// Wallet name (uses default if not specified)
        name: Option<String>,
    },
    
    /// Show wallet details
    Info {
        /// Wallet name
        name: String,
    },
    
    /// Sign a message
    Sign {
        /// Message to sign
        message: String,
        
        /// Wallet name (uses default if not specified)
        #[arg(short, long)]
        wallet: Option<String>,
    },
    
    /// Verify a signature
    Verify {
        /// Original message
        message: String,
        
        /// Signature in hex format
        signature: String,
        
        /// Public key or address
        #[arg(short, long)]
        pubkey: Option<String>,
    },
    
    /// Regenerate wallet from mnemonic
    Regen {
        /// Wallet name
        name: String,
        
        /// Mnemonic phrase (will prompt if not provided)
        #[arg(short, long)]
        mnemonic: Option<String>,
    },
    
    /// Create a new hotkey
    NewHotkey {
        /// Wallet name
        wallet: String,
        
        /// Hotkey name
        name: String,
    },
    
    /// List hotkeys for a wallet
    ListHotkeys {
        /// Wallet name
        wallet: String,
    },
}

/// Execute wallet command
pub async fn execute(ctx: &AppContext, cmd: WalletCommand, format: OutputFormat) -> Result<()> {
    let service = WalletService::new(ctx.wallet_dir().clone());
    
    match cmd {
        WalletCommand::Create { name, words, no_password } => {
            create_wallet(&service, &name, words, no_password, format).await
        }
        WalletCommand::List => {
            list_wallets(&service, format).await
        }
        WalletCommand::Balance { name } => {
            show_balance(ctx, &service, name.as_deref(), format).await
        }
        WalletCommand::Info { name } => {
            show_wallet_info(&service, &name, format).await
        }
        WalletCommand::Sign { message, wallet } => {
            sign_message(&service, &message, wallet.as_deref(), format).await
        }
        WalletCommand::Verify { message, signature, pubkey } => {
            verify_signature(&service, &message, &signature, pubkey.as_deref(), format).await
        }
        WalletCommand::Regen { name, mnemonic } => {
            regen_wallet(&service, &name, mnemonic.as_deref(), format).await
        }
        WalletCommand::NewHotkey { wallet, name } => {
            create_hotkey(&service, &wallet, &name, format).await
        }
        WalletCommand::ListHotkeys { wallet } => {
            list_hotkeys(&service, &wallet, format).await
        }
    }
}

async fn create_wallet(
    service: &WalletService,
    name: &str,
    words: u8,
    no_password: bool,
    format: OutputFormat,
) -> Result<()> {
    let password = if no_password {
        String::new()
    } else {
        prompt_password("Enter wallet password: ")?
    };

    let wallet = service.create_wallet(name, words, &password)?;
    let address = wallet.hotkey().to_string(); // Hotkey address (coldkey needs unlock)
    
    match format {
        OutputFormat::Text => {
            println!("✓ Wallet '{}' created successfully", name);
            println!("  Coldkey: {}", address);
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "success": true,
                "wallet": name,
                "coldkey": address
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

async fn list_wallets(service: &WalletService, format: OutputFormat) -> Result<()> {
    let wallets = service.list_wallets()?;
    
    match format {
        OutputFormat::Text => {
            if wallets.is_empty() {
                println!("No wallets found");
            } else {
                println!("Wallets:");
                for wallet in wallets {
                    println!("  • {}", wallet);
                }
            }
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "wallets": wallets
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

async fn show_balance(
    ctx: &AppContext,
    service: &WalletService,
    name: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let wallet_name = name
        .map(String::from)
        .or_else(|| ctx.config().wallet.default_wallet.clone())
        .ok_or_else(|| crate::errors::Error::wallet("No wallet specified"))?;

    let wallet = service.load_wallet(&wallet_name)?;
    let address = read_coldkey_address(&wallet.path);
    
    // For balance, we need to connect to the network
    // For now, just show the address
    match format {
        OutputFormat::Text => {
            println!("Wallet: {}", wallet_name);
            println!("Address: {}", address);
            println!("Balance: Connect to network to fetch balance");
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "wallet": wallet_name,
                "address": address,
                "balance_tao": null,
                "balance_rao": null,
                "note": "Connect to network to fetch balance"
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

async fn show_wallet_info(service: &WalletService, name: &str, format: OutputFormat) -> Result<()> {
    let wallet = service.load_wallet(name)?;
    let coldkey = read_coldkey_address(&wallet.path);
    let hotkeys = service.list_hotkeys(name)?;
    
    match format {
        OutputFormat::Text => {
            println!("Wallet: {}", name);
            println!("Coldkey: {}", coldkey);
            println!("Hotkeys:");
            if hotkeys.is_empty() {
                println!("  (none)");
            } else {
                for hk in &hotkeys {
                    println!("  • {}", hk);
                }
            }
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "wallet": name,
                "coldkey": coldkey,
                "hotkeys": hotkeys
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

async fn sign_message(
    service: &WalletService,
    message: &str,
    wallet_name: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let name = wallet_name.unwrap_or("default");
    let password = prompt_password("Enter wallet password: ")?;
    
    let signature = service.sign_message(name, message, &password)?;
    
    match format {
        OutputFormat::Text => {
            println!("Signature: {}", signature);
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "message": message,
                "signature": signature
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

async fn verify_signature(
    service: &WalletService,
    message: &str,
    signature: &str,
    pubkey: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let valid = service.verify_signature(message, signature, pubkey)?;
    
    match format {
        OutputFormat::Text => {
            if valid {
                println!("✓ Signature is valid");
            } else {
                println!("✗ Signature is invalid");
            }
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "valid": valid,
                "message": message
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

async fn regen_wallet(
    service: &WalletService,
    name: &str,
    mnemonic: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    let mnemonic = match mnemonic {
        Some(m) => m.to_string(),
        None => prompt_input("Enter mnemonic phrase: ")?,
    };
    
    let password = prompt_password("Enter new wallet password: ")?;
    
    let wallet = service.regen_wallet(name, &mnemonic, &password)?;
    let address = read_coldkey_address(&wallet.path);
    
    match format {
        OutputFormat::Text => {
            println!("✓ Wallet '{}' regenerated successfully", name);
            println!("  Coldkey: {}", address);
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "success": true,
                "wallet": name,
                "coldkey": address
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

async fn create_hotkey(
    service: &WalletService,
    wallet: &str,
    name: &str,
    format: OutputFormat,
) -> Result<()> {
    let password = prompt_password("Enter wallet password: ")?;
    
    let address = service.create_hotkey(wallet, name, &password)?;
    
    match format {
        OutputFormat::Text => {
            println!("✓ Hotkey '{}' created for wallet '{}'", name, wallet);
            println!("  Address: {}", address);
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "success": true,
                "wallet": wallet,
                "hotkey": name,
                "address": address
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

async fn list_hotkeys(service: &WalletService, wallet: &str, format: OutputFormat) -> Result<()> {
    let hotkeys = service.list_hotkeys(wallet)?;
    
    match format {
        OutputFormat::Text => {
            if hotkeys.is_empty() {
                println!("No hotkeys found for wallet '{}'", wallet);
            } else {
                println!("Hotkeys for '{}':", wallet);
                for hk in hotkeys {
                    println!("  • {}", hk);
                }
            }
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "wallet": wallet,
                "hotkeys": hotkeys
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    
    Ok(())
}

// Helper functions for prompts
fn prompt_password(prompt: &str) -> Result<String> {
    dialoguer::Password::new()
        .with_prompt(prompt)
        .interact()
        .map_err(|e| crate::errors::Error::ui(e.to_string()))
}

fn prompt_input(prompt: &str) -> Result<String> {
    dialoguer::Input::new()
        .with_prompt(prompt)
        .interact_text()
        .map_err(|e| crate::errors::Error::ui(e.to_string()))
}
