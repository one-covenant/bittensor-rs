//! # CLI Module
//!
//! Command-line interface implementation using clap.

pub mod crowd;
pub mod root;
pub mod stake;
pub mod subnet;
pub mod transfer;
pub mod wallet;
pub mod weights;

use crate::errors::Result;
use clap::{Parser, Subcommand};

/// Lightning Tensor - High-performance CLI for Bittensor
#[derive(Parser, Debug)]
#[command(name = "lt")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Network to connect to: finney, test, local, or custom URL
    #[arg(short, long, global = true, default_value = "finney")]
    pub network: String,

    /// Wallet name to use
    #[arg(short, long, global = true)]
    pub wallet: Option<String>,

    /// Hotkey name to use
    #[arg(short = 'H', long, global = true)]
    pub hotkey: Option<String>,

    /// Subnet netuid
    #[arg(short = 'u', long, global = true)]
    pub netuid: Option<u16>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output format: text, json
    #[arg(long, global = true, default_value = "text")]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

/// Output format for CLI commands
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch interactive TUI
    Tui,

    /// Wallet operations
    #[command(subcommand)]
    Wallet(wallet::WalletCommand),

    /// Staking operations
    #[command(subcommand)]
    Stake(stake::StakeCommand),

    /// Transfer TAO
    Transfer(transfer::TransferArgs),

    /// Subnet operations
    #[command(subcommand)]
    Subnet(subnet::SubnetCommand),

    /// Weight operations
    #[command(subcommand)]
    Weights(weights::WeightsCommand),

    /// Root network operations
    #[command(subcommand)]
    Root(root::RootCommand),

    /// Crowdfunding operations
    #[command(subcommand)]
    Crowd(crowd::CrowdCommand),
}

impl Cli {
    /// Execute the CLI command
    pub async fn execute(self) -> Result<()> {
        // Build context with CLI options
        let mut builder = crate::context::AppContextBuilder::new().with_network(&self.network);

        if let Some(wallet) = &self.wallet {
            builder = builder.with_wallet(wallet);
        }
        if let Some(hotkey) = &self.hotkey {
            builder = builder.with_hotkey(hotkey);
        }
        if let Some(netuid) = self.netuid {
            builder = builder.with_netuid(netuid);
        }

        let ctx = builder.build()?;

        match self.command {
            Commands::Tui => crate::tui::run(ctx).await,
            Commands::Wallet(cmd) => wallet::execute(&ctx, cmd, self.output).await,
            Commands::Stake(cmd) => stake::execute(&ctx, cmd, self.output).await,
            Commands::Transfer(args) => transfer::execute(&ctx, args, self.output).await,
            Commands::Subnet(cmd) => subnet::execute(&ctx, cmd, self.output).await,
            Commands::Weights(cmd) => weights::execute(&ctx, cmd, self.output).await,
            Commands::Root(cmd) => root::execute(&ctx, cmd, self.output).await,
            Commands::Crowd(cmd) => crowd::execute(&ctx, cmd, self.output).await,
        }
    }
}

/// Run the CLI
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    cli.execute().await
}
