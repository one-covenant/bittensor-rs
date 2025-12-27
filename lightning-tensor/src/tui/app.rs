//! # TUI Application State
//!
//! Main application state and event loop for the TUI.

use crate::context::AppContext;
use crate::errors::Result;
use crate::tui::components::AnimationState;
use crate::tui::views;
use bittensor_rs::SubnetInfo;
use bittensor_wallet::Wallet;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::backend::Backend;
use ratatui::widgets::ListState;
use ratatui::Terminal;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;

/// Application state enumeration
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppState {
    Home,
    Wallet,
    Stake,
    Subnet,
    Metagraph,
    Transfer,
    Weights,
    Root,
}

/// Async operation result
#[derive(Debug)]
pub enum AsyncResult {
    WalletLoaded(Result<Wallet>),
    BalanceLoaded(Result<f64>),
    SubnetsLoaded(Result<Vec<SubnetInfo>>),
    Message(String),
    Error(String),
}

/// Main TUI application
pub struct App {
    /// Application context
    pub ctx: AppContext,
    
    /// Current view state
    pub state: AppState,
    
    /// Should quit the application
    pub should_quit: bool,
    
    /// Input mode active
    pub input_mode: bool,
    
    /// Current input buffer
    pub input_buffer: String,
    
    /// Input prompt text
    pub input_prompt: String,
    
    /// Is password input (masked)
    pub is_password_input: bool,
    
    /// Status messages
    pub messages: Arc<Mutex<Vec<String>>>,
    
    /// Loaded wallets
    pub wallets: Vec<Wallet>,
    
    /// Wallet list state
    pub wallet_list_state: ListState,
    
    /// Selected wallet index
    pub selected_wallet: Option<usize>,
    
    /// Loaded subnets
    pub subnets: Vec<SubnetInfo>,
    
    /// Selected subnet index
    pub selected_subnet: Option<usize>,
    
    /// Animation state
    pub animation_state: AnimationState,
    
    /// Async result channel
    pub async_tx: Sender<AsyncResult>,
    pub async_rx: Receiver<AsyncResult>,
    
    /// Loading indicator
    pub is_loading: bool,
    
    /// Current netuid for operations
    pub current_netuid: u16,
}

impl App {
    /// Create a new TUI application
    pub fn new(ctx: AppContext) -> Result<Self> {
        let (async_tx, async_rx) = channel(100);
        
        let wallet_dir = ctx.wallet_dir().clone();
        
        // Load wallets
        let wallets = load_wallets(&wallet_dir);
        
        let mut wallet_list_state = ListState::default();
        if !wallets.is_empty() {
            wallet_list_state.select(Some(0));
        }
        
        Ok(Self {
            ctx,
            state: AppState::Home,
            should_quit: false,
            input_mode: false,
            input_buffer: String::new(),
            input_prompt: String::new(),
            is_password_input: false,
            messages: Arc::new(Mutex::new(Vec::new())),
            wallets,
            wallet_list_state,
            selected_wallet: None,
            subnets: Vec::new(),
            selected_subnet: None,
            animation_state: AnimationState::new(),
            async_tx,
            async_rx,
            is_loading: false,
            current_netuid: 1,
        })
    }
    
    /// Get selected wallet
    pub fn selected_wallet(&self) -> Option<&Wallet> {
        self.selected_wallet.and_then(|i| self.wallets.get(i))
    }
    
    /// Add a message
    pub async fn add_message(&self, msg: String) {
        let mut messages = self.messages.lock().await;
        messages.push(msg);
        // Keep last 10 messages
        if messages.len() > 10 {
            messages.remove(0);
        }
    }
    
    /// Run the application event loop
    pub async fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            // Draw UI
            terminal.draw(|f| {
                views::draw(f, self);
            })?;
            
            // Handle events with timeout
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    // Global quit with Ctrl+C or Ctrl+Q
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        match key.code {
                            KeyCode::Char('c') | KeyCode::Char('q') => {
                                self.should_quit = true;
                            }
                            _ => {}
                        }
                    } else if self.input_mode {
                        self.handle_input_mode(key.code).await;
                    } else {
                        self.handle_normal_mode(key.code).await?;
                    }
                }
            }
            
            // Check for async results
            while let Ok(result) = self.async_rx.try_recv() {
                self.handle_async_result(result).await;
            }
            
            // Update animation
            self.animation_state.update();
            
            if self.should_quit {
                return Ok(());
            }
        }
    }
    
    /// Handle input mode key events
    async fn handle_input_mode(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter => {
                let input = std::mem::take(&mut self.input_buffer);
                self.input_mode = false;
                self.is_password_input = false;
                // Process input based on context
                self.process_input(input).await;
            }
            KeyCode::Char(c) => {
                self.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.input_buffer.pop();
            }
            KeyCode::Esc => {
                self.input_mode = false;
                self.is_password_input = false;
                self.input_buffer.clear();
                self.add_message("Cancelled".to_string()).await;
            }
            _ => {}
        }
    }
    
    /// Handle normal mode key events
    async fn handle_normal_mode(&mut self, key: KeyCode) -> Result<()> {
        match key {
            KeyCode::Char('q') => {
                if self.state == AppState::Home {
                    self.should_quit = true;
                } else {
                    self.state = AppState::Home;
                }
            }
            KeyCode::Esc => {
                if self.state != AppState::Home {
                    self.state = AppState::Home;
                }
            }
            _ => {
                // Delegate to view-specific handlers
                match self.state {
                    AppState::Home => self.handle_home_input(key).await,
                    AppState::Wallet => self.handle_wallet_input(key).await,
                    AppState::Stake => self.handle_stake_input(key).await,
                    AppState::Subnet => self.handle_subnet_input(key).await,
                    AppState::Metagraph => self.handle_metagraph_input(key).await,
                    AppState::Transfer => self.handle_transfer_input(key).await,
                    AppState::Weights => self.handle_weights_input(key).await,
                    AppState::Root => self.handle_root_input(key).await,
                }
            }
        }
        Ok(())
    }
    
    /// Handle home view input
    async fn handle_home_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('w') => self.state = AppState::Wallet,
            KeyCode::Char('s') => self.state = AppState::Stake,
            KeyCode::Char('n') => self.state = AppState::Subnet,
            KeyCode::Char('t') => self.state = AppState::Transfer,
            KeyCode::Char('g') => self.state = AppState::Weights,
            KeyCode::Char('r') => self.state = AppState::Root,
            _ => {}
        }
    }
    
    /// Handle wallet view input
    async fn handle_wallet_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(selected) = self.wallet_list_state.selected() {
                    if selected > 0 {
                        self.wallet_list_state.select(Some(selected - 1));
                    } else if !self.wallets.is_empty() {
                        self.wallet_list_state.select(Some(self.wallets.len() - 1));
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(selected) = self.wallet_list_state.selected() {
                    if selected < self.wallets.len().saturating_sub(1) {
                        self.wallet_list_state.select(Some(selected + 1));
                    } else {
                        self.wallet_list_state.select(Some(0));
                    }
                }
            }
            KeyCode::Enter => {
                self.selected_wallet = self.wallet_list_state.selected();
                if self.selected_wallet.is_some() {
                    self.add_message("Wallet selected".to_string()).await;
                }
            }
            KeyCode::Char('c') => {
                self.input_mode = true;
                self.input_prompt = "Enter wallet name: ".to_string();
            }
            KeyCode::Char('b') => {
                // Fetch balance for selected wallet
                if let Some(wallet) = self.selected_wallet() {
                    self.add_message(format!("Fetching balance for {}...", wallet.name)).await;
                }
            }
            _ => {}
        }
    }
    
    /// Handle stake view input
    async fn handle_stake_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('a') => {
                self.input_mode = true;
                self.input_prompt = "Amount to stake (TAO): ".to_string();
            }
            KeyCode::Char('r') => {
                self.input_mode = true;
                self.input_prompt = "Amount to unstake (TAO): ".to_string();
            }
            _ => {}
        }
    }
    
    /// Handle subnet view input
    async fn handle_subnet_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(selected) = self.selected_subnet {
                    if selected > 0 {
                        self.selected_subnet = Some(selected - 1);
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(selected) = self.selected_subnet {
                    if selected < self.subnets.len().saturating_sub(1) {
                        self.selected_subnet = Some(selected + 1);
                    }
                } else if !self.subnets.is_empty() {
                    self.selected_subnet = Some(0);
                }
            }
            KeyCode::Enter => {
                if let Some(idx) = self.selected_subnet {
                    if let Some(subnet) = self.subnets.get(idx) {
                        self.current_netuid = subnet.netuid;
                        self.state = AppState::Metagraph;
                    }
                }
            }
            KeyCode::Char('r') => {
                self.add_message("Refreshing subnets...".to_string()).await;
                // TODO: Trigger subnet refresh
            }
            _ => {}
        }
    }
    
    /// Handle metagraph view input
    async fn handle_metagraph_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('r') => {
                self.add_message("Refreshing metagraph...".to_string()).await;
            }
            _ => {}
        }
    }
    
    /// Handle transfer view input
    async fn handle_transfer_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('t') => {
                self.input_mode = true;
                self.input_prompt = "Destination address: ".to_string();
            }
            _ => {}
        }
    }
    
    /// Handle weights view input
    async fn handle_weights_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('s') => {
                self.input_mode = true;
                self.input_prompt = "UIDs (comma-separated): ".to_string();
            }
            _ => {}
        }
    }
    
    /// Handle root view input
    async fn handle_root_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('r') => {
                self.add_message("Root registration...".to_string()).await;
            }
            _ => {}
        }
    }
    
    /// Process input after Enter
    async fn process_input(&mut self, _input: String) {
        // Context-specific input processing
        self.add_message("Input received".to_string()).await;
    }
    
    /// Handle async operation results
    async fn handle_async_result(&mut self, result: AsyncResult) {
        match result {
            AsyncResult::Message(msg) => {
                self.add_message(msg).await;
            }
            AsyncResult::Error(err) => {
                self.add_message(format!("Error: {}", err)).await;
            }
            AsyncResult::WalletLoaded(res) => {
                match res {
                    Ok(wallet) => {
                        self.add_message(format!("Loaded wallet: {}", wallet.name)).await;
                    }
                    Err(e) => {
                        self.add_message(format!("Failed to load wallet: {}", e)).await;
                    }
                }
            }
            AsyncResult::BalanceLoaded(res) => {
                match res {
                    Ok(balance) => {
                        self.add_message(format!("Balance: {:.4} TAO", balance)).await;
                    }
                    Err(e) => {
                        self.add_message(format!("Failed to get balance: {}", e)).await;
                    }
                }
            }
            AsyncResult::SubnetsLoaded(res) => {
                match res {
                    Ok(subnets) => {
                        self.subnets = subnets;
                        self.add_message(format!("Loaded {} subnets", self.subnets.len())).await;
                    }
                    Err(e) => {
                        self.add_message(format!("Failed to load subnets: {}", e)).await;
                    }
                }
            }
        }
        self.is_loading = false;
    }
}

/// Load wallets from directory
fn load_wallets(wallet_dir: &std::path::PathBuf) -> Vec<Wallet> {
    let mut wallets = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(wallet_dir) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    let wallet_name = entry.file_name().to_string_lossy().into_owned();
                    let wallet_path = entry.path();
                    let wallet = Wallet::new(&wallet_name, wallet_path);
                    wallets.push(wallet);
                }
            }
        }
    }
    
    wallets.sort_by(|a, b| a.name.cmp(&b.name));
    wallets
}

