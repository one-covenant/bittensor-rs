use bittensor_wallet::{Wallet, WalletError};
use clap::{Parser, Subcommand};
use sp_core::crypto::Ss58Codec;
use sp_core::sr25519;
use sp_core::ByteArray;
use std::path::PathBuf;
use log::info;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new wallet
    Create {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        path: PathBuf,
        #[clap(short, long, default_value = "12")]
        words: u32,
        #[clap(short, long)]
        password: String,
    },
    /// Add a new hotkey to an existing wallet
    AddHotkey {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        wallet_name: String,
        #[clap(short, long)]
        wallet_path: PathBuf,
        #[clap(short, long)]
        _password: String,
    },
    /// Regenerate a wallet from a mnemonic phrase
    RegenerateWallet {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        path: PathBuf,
        #[clap(short, long)]
        mnemonic: String,
        #[clap(short, long)]
        password: String,
    },
    /// Change the password of an existing wallet
    ChangePassword {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        path: PathBuf,
        #[clap(short, long)]
        old_password: String,
        #[clap(short, long)]
        new_password: String,
    },
    /// Get information about the coldkey in a wallet
    GetColdkeyInfo {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        path: PathBuf,
        #[clap(short, long)]
        password: String,
    },
    /// Get information about a hotkey in a wallet
    GetHotkeyInfo {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        wallet_name: String,
        #[clap(short, long)]
        wallet_path: PathBuf,
    },
    /// Show wallet information including all coldkeys and attached hotkeys
    ShowWalletInfo {
        #[clap(short, long)]
        name: String,
        #[clap(short, long)]
        path: PathBuf,
        #[clap(short, long)]
        password: String,
    },
}

fn main() -> Result<(), WalletError> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Create {
            name,
            path,
            words,
            password,
        } => {
            let mut wallet = Wallet::new(name.clone(), path.clone())?;
            wallet.create_new_wallet(password)?;
            info!("Wallet created successfully with {} words", words);
        }
        Commands::AddHotkey {
            name,
            wallet_name,
            wallet_path,
            _password,
        } => {
            let mut wallet = Wallet::new(wallet_name.clone(), wallet_path.clone())?;
            wallet.create_new_hotkey(name)?;
            info!("Hotkey added successfully");
        }
        Commands::RegenerateWallet {
            name,
            path,
            mnemonic,
            password,
        } => {
            let mut wallet = Wallet::new(name.clone(), path.clone())?;
            wallet.regenerate_wallet(mnemonic, password)?;
            info!("Wallet regenerated successfully");
        }
        Commands::ChangePassword {
            name,
            path,
            old_password,
            new_password,
        } => {
            let mut wallet = Wallet::new(name.clone(), path.clone())?;
            wallet.change_password(old_password, new_password)?;
            info!("Password changed successfully");
        }
        Commands::GetColdkeyInfo {
            name,
            path,
            password,
        } => {
            let wallet = Wallet::new(name.clone(), path.clone())?;
            let coldkey = wallet.get_coldkey(password)?;
            info!("Coldkey public key: {:?}", coldkey.public);
            info!(
                "Coldkey SS58 address: {}",
                sr25519::Public::from_slice(&coldkey.public)
                    .expect("Invalid public key")
                    .to_ss58check()
            );
        }
        Commands::GetHotkeyInfo {
            name,
            wallet_name,
            wallet_path,
        } => {
            let wallet = Wallet::new(wallet_name.clone(), wallet_path.clone())?;
            let hotkey = wallet.get_hotkey(name)?;
            info!("Hotkey public key: {:?}", hotkey.public);
            info!("Hotkey SS58 address: {}", hotkey.public.to_ss58check());
        }
        Commands::ShowWalletInfo {
            name,
            path,
            password,
        } => {
            let wallet = Wallet::new(name.clone(), path.clone())?;

            // Display coldkey information
            let coldkey = wallet.get_coldkey(password)?;
            info!("Coldkey Information:");
            info!("  Public key: {:?}", coldkey.public);
            info!("  SS58 address: {}", sr25519::Public::from_slice(&coldkey.public).expect("Invalid public key").to_ss58check());

            // Display hotkey information
            info!("\nHotkeys:");
            let hotkeys = wallet.get_hotkeys()?;
            for (name, hotkey) in hotkeys {
                info!("  Hotkey: {}", name);
                info!("    Public key: {:?}", hotkey.public);
                info!("    SS58 address: {}", hotkey.public.to_ss58check());
            }
        }
    }
    Ok(())
}
