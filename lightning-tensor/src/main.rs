//! # Lightning Tensor
//!
//! High-performance CLI/TUI for the Bittensor network.
//!
//! ## Usage
//!
//! ```bash
//! # Launch TUI
//! lt tui
//!
//! # CLI commands
//! lt wallet list
//! lt stake add --hotkey <addr> --amount 1.0
//! lt subnet list
//! lt transfer --to <addr> --amount 1.0
//! ```

use lightning_tensor::cli;
use lightning_tensor::errors::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "warn");
    }
    env_logger::init();

    // Run CLI
    cli::run().await
}
