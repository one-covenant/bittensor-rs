//! # TUI Application State
//!
//! Main application state and event loop for the TUI.

use crate::context::AppContext;
use crate::errors::Result;
use crate::tui::components::AnimationState;
use crate::tui::views;
use bittensor_rs::{DynamicSubnetInfo, NeuronDiscovery};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::backend::Backend;
use ratatui::widgets::{ListState, TableState};
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

/// Wallet info for display (since Wallet from bittensor_wallet isn't available)
#[derive(Debug, Clone)]
pub struct WalletInfo {
    pub name: String,
    pub path: std::path::PathBuf,
    pub coldkey_address: Option<String>,
    pub hotkeys: Vec<String>,
}

/// Stake info per subnet for display
#[derive(Debug, Clone)]
pub struct WalletStakeInfo {
    pub netuid: u16,
    pub hotkey: String,
    pub stake_tao: f64,
    pub emission_tao: f64,
}

/// Neuron display info
#[derive(Debug, Clone)]
pub struct NeuronDisplay {
    pub uid: u16,
    pub hotkey: String,
    pub coldkey: String,
    pub stake: f64,
    pub is_validator: bool,
    pub ip: String,
    pub port: u16,
    pub incentive: f64,
    pub emission: f64,
    pub trust: f64,
    pub consensus: f64,
    pub dividends: f64,
}

/// Async operation result
#[derive(Debug)]
pub enum AsyncResult {
    Connected(std::result::Result<(), String>),
    WalletLoaded(Result<WalletInfo>),
    BalanceLoaded { wallet_idx: usize, balance: Result<f64> },
    StakeLoaded { wallet_idx: usize, stakes: Result<Vec<WalletStakeInfo>> },
    SubnetsLoaded(Result<Vec<DynamicSubnetInfo>>),
    MetagraphLoaded { netuid: u16, neurons: Result<Vec<NeuronDisplay>> },
    Message(String),
    Error(String),
}

/// Main TUI application
pub struct App {
    /// Application context (Arc wrapped for async sharing)
    pub ctx: Arc<AppContext>,
    
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
    pub wallets: Vec<WalletInfo>,
    
    /// Wallet balances (indexed by wallet position)
    pub wallet_balances: Vec<Option<f64>>,
    
    /// Wallet stakes per subnet (indexed by wallet position)
    pub wallet_stakes: Vec<Vec<WalletStakeInfo>>,
    
    /// Wallet list state
    pub wallet_list_state: ListState,
    
    /// Selected wallet index
    pub selected_wallet: Option<usize>,
    
    /// Loaded subnets (with DTAO pricing info)
    pub subnets: Vec<DynamicSubnetInfo>,
    
    /// Subnet table state (for navigation)
    pub subnet_list_state: TableState,
    
    /// Selected subnet index
    pub selected_subnet: Option<usize>,
    
    /// Metagraph neurons for current subnet
    pub metagraph_neurons: Vec<NeuronDisplay>,
    
    /// Metagraph table state (for scrolling)
    pub metagraph_table_state: TableState,
    
    /// Animation state
    pub animation_state: AnimationState,
    
    /// Async result channel
    pub async_tx: Sender<AsyncResult>,
    pub async_rx: Receiver<AsyncResult>,
    
    /// Loading indicator
    pub is_loading: bool,
    
    /// Loading message
    pub loading_message: String,
    
    /// Current netuid for operations
    pub current_netuid: u16,
    
    /// Connected to network
    pub is_connected: bool,
    
    /// Transfer destination address
    pub transfer_dest: String,
    
    /// Transfer amount
    pub transfer_amount: String,
}

impl App {
    /// Create a new TUI application
    pub fn new(ctx: Arc<AppContext>) -> Result<Self> {
        let (async_tx, async_rx) = channel(100);
        
        let wallet_dir = ctx.wallet_dir().clone();
        
        // Load wallets
        let wallets = load_wallets(&wallet_dir);
        let wallet_balances = vec![None; wallets.len()];
        let wallet_stakes = vec![Vec::new(); wallets.len()];
        
        let mut wallet_list_state = ListState::default();
        if !wallets.is_empty() {
            wallet_list_state.select(Some(0));
        }
        
        let mut subnet_list_state = TableState::default();
        subnet_list_state.select(Some(0));
        
        let mut metagraph_table_state = TableState::default();
        metagraph_table_state.select(Some(0));
        
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
            wallet_balances,
            wallet_stakes,
            wallet_list_state,
            selected_wallet: None,
            subnets: Vec::new(),
            subnet_list_state,
            selected_subnet: None,
            metagraph_neurons: Vec::new(),
            metagraph_table_state,
            animation_state: AnimationState::new(),
            async_tx,
            async_rx,
            is_loading: false,
            loading_message: String::new(),
            current_netuid: 1,
            is_connected: false,
            transfer_dest: String::new(),
            transfer_amount: String::new(),
        })
    }
    
    /// Get selected wallet info
    pub fn selected_wallet_info(&self) -> Option<&WalletInfo> {
        self.selected_wallet.and_then(|i| self.wallets.get(i))
    }
    
    /// Get selected wallet balance
    pub fn selected_wallet_balance(&self) -> Option<f64> {
        self.selected_wallet.and_then(|i| self.wallet_balances.get(i).copied().flatten())
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
        // Auto-connect on startup
        if !self.is_connected && !self.is_loading {
            self.auto_connect().await;
        }
        
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
            KeyCode::Char('n') => {
                self.state = AppState::Subnet;
                if self.subnets.is_empty() && !self.is_loading {
                    self.fetch_subnets();
                }
            }
            KeyCode::Char('m') => {
                self.state = AppState::Metagraph;
                if self.metagraph_neurons.is_empty() && !self.is_loading {
                    self.fetch_metagraph();
                }
            }
            KeyCode::Char('t') => self.state = AppState::Transfer,
            KeyCode::Char('g') => self.state = AppState::Weights,
            KeyCode::Char('r') => self.state = AppState::Root,
            KeyCode::Char('c') => {
                // Connect to network
                if !self.is_connected && !self.is_loading {
                    self.connect_to_network().await;
                }
            }
            _ => {}
        }
    }
    
    /// Connect to network
    async fn connect_to_network(&mut self) {
        self.start_loading("Connecting to network...");
        match self.ctx.connect_with_defaults().await {
            Ok(_) => {
                self.is_connected = true;
                self.add_message("✓ Connected to network".to_string()).await;
            }
            Err(e) => {
                self.add_message(format!("✗ Connection failed: {}", e)).await;
            }
        }
        self.is_loading = false;
    }
    
    /// Auto-connect to network in background
    async fn auto_connect(&mut self) {
        // Check if we have wallets - if not, show guidance
        if self.wallets.is_empty() {
            self.add_message("No wallets found. Create one with 'lt wallet create <name>'".to_string()).await;
            self.add_message("Press 'c' to try connecting after creating a wallet.".to_string()).await;
            return;
        }
        
        let tx = self.async_tx.clone();
        let ctx = Arc::clone(&self.ctx);
        let network = ctx.network_name().to_string();
        
        self.add_message(format!("⏳ Connecting to {}...", network)).await;
        self.start_loading(&format!("Connecting to {}...", network));
        
        tokio::spawn(async move {
            match ctx.connect_with_defaults().await {
                Ok(_) => {
                    let _ = tx.send(AsyncResult::Connected(Ok(()))).await;
                }
                Err(e) => {
                    let _ = tx.send(AsyncResult::Connected(Err(format!("{}", e)))).await;
                }
            }
        });
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
                if let Some(idx) = self.selected_wallet {
                    if let Some(w) = self.wallets.get(idx) {
                        self.add_message(format!("✓ Selected: {}", w.name)).await;
                    }
                }
            }
            KeyCode::Char('c') => {
                self.input_mode = true;
                self.input_prompt = "Enter wallet name: ".to_string();
            }
            KeyCode::Char('b') => {
                // Fetch balance for currently highlighted wallet
                if let Some(idx) = self.wallet_list_state.selected() {
                    if !self.is_loading {
                        self.fetch_balance(idx);
                    }
                }
            }
            KeyCode::Char('B') => {
                // Fetch all balances
                if !self.is_loading {
                    for i in 0..self.wallets.len() {
                        self.fetch_balance(i);
                    }
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
                let i = match self.subnet_list_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.subnets.len().saturating_sub(1)
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.subnet_list_state.select(Some(i));
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let i = match self.subnet_list_state.selected() {
                    Some(i) => {
                        if i >= self.subnets.len().saturating_sub(1) {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.subnet_list_state.select(Some(i));
            }
            KeyCode::Enter => {
                if let Some(idx) = self.subnet_list_state.selected() {
                    if let Some(subnet) = self.subnets.get(idx) {
                        self.current_netuid = subnet.netuid;
                        self.metagraph_neurons.clear();
                        self.state = AppState::Metagraph;
                        self.fetch_metagraph();
                    }
                }
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                if !self.is_loading {
                    self.fetch_subnets();
                }
            }
            _ => {}
        }
    }
    
    /// Handle metagraph view input
    async fn handle_metagraph_input(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                let i = match self.metagraph_table_state.selected() {
                    Some(i) => i.saturating_sub(1),
                    None => 0,
                };
                self.metagraph_table_state.select(Some(i));
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let i = match self.metagraph_table_state.selected() {
                    Some(i) => {
                        if i >= self.metagraph_neurons.len().saturating_sub(1) {
                            i
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.metagraph_table_state.select(Some(i));
            }
            KeyCode::PageUp => {
                let i = match self.metagraph_table_state.selected() {
                    Some(i) => i.saturating_sub(20),
                    None => 0,
                };
                self.metagraph_table_state.select(Some(i));
            }
            KeyCode::PageDown => {
                let i = match self.metagraph_table_state.selected() {
                    Some(i) => {
                        std::cmp::min(i + 20, self.metagraph_neurons.len().saturating_sub(1))
                    }
                    None => 0,
                };
                self.metagraph_table_state.select(Some(i));
            }
            KeyCode::Home => {
                self.metagraph_table_state.select(Some(0));
            }
            KeyCode::End => {
                if !self.metagraph_neurons.is_empty() {
                    self.metagraph_table_state.select(Some(self.metagraph_neurons.len() - 1));
                }
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                if !self.is_loading {
                    self.fetch_metagraph();
                }
            }
            KeyCode::Char('/') => {
                // TODO: Search
                self.add_message("Search not yet implemented".to_string()).await;
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
            AsyncResult::Connected(res) => {
                match res {
                    Ok(()) => {
                        self.is_connected = true;
                        self.add_message("✓ Connected to network".to_string()).await;
                        // Auto-load data after connecting
                        self.fetch_subnets();
                        self.fetch_all_balances();
                        self.fetch_all_stakes();
                    }
                    Err(e) => {
                        self.add_message(format!("✗ Connection failed: {}", e)).await;
                    }
                }
            }
            AsyncResult::Message(msg) => {
                self.add_message(msg).await;
            }
            AsyncResult::Error(err) => {
                self.add_message(format!("✗ {}", err)).await;
            }
            AsyncResult::WalletLoaded(res) => {
                match res {
                    Ok(wallet) => {
                        self.add_message(format!("✓ Loaded wallet: {}", wallet.name)).await;
                    }
                    Err(e) => {
                        self.add_message(format!("✗ Failed to load wallet: {}", e)).await;
                    }
                }
            }
            AsyncResult::BalanceLoaded { wallet_idx, balance } => {
                match balance {
                    Ok(bal) => {
                        if wallet_idx < self.wallet_balances.len() {
                            self.wallet_balances[wallet_idx] = Some(bal);
                        }
                        // Silent update - don't spam messages for batch loads
                    }
                    Err(_e) => {
                        // Silent failure for batch loads
                    }
                }
                self.stop_loading();
            }
            AsyncResult::StakeLoaded { wallet_idx, stakes } => {
                match stakes {
                    Ok(s) => {
                        if wallet_idx < self.wallet_stakes.len() {
                            self.wallet_stakes[wallet_idx] = s;
                        }
                    }
                    Err(_e) => {
                        // Silent failure
                    }
                }
                self.stop_loading();
            }
            AsyncResult::SubnetsLoaded(res) => {
                match res {
                    Ok(subnets) => {
                        let count = subnets.len();
                        self.subnets = subnets;
                        if !self.subnets.is_empty() {
                            self.subnet_list_state.select(Some(0));
                        }
                        self.add_message(format!("✓ Loaded {} subnets", count)).await;
                    }
                    Err(e) => {
                        self.add_message(format!("✗ Failed to load subnets: {}", e)).await;
                    }
                }
            }
            AsyncResult::MetagraphLoaded { netuid, neurons } => {
                match neurons {
                    Ok(n) => {
                        let count = n.len();
                        self.metagraph_neurons = n;
                        if !self.metagraph_neurons.is_empty() {
                            self.metagraph_table_state.select(Some(0));
                        }
                        self.add_message(format!("✓ Loaded {} neurons for subnet {}", count, netuid)).await;
                    }
                    Err(e) => {
                        self.add_message(format!("✗ Failed to load metagraph: {}", e)).await;
                    }
                }
            }
        }
        self.is_loading = false;
        self.loading_message.clear();
    }
    
    /// Start loading with message
    pub fn start_loading(&mut self, message: &str) {
        self.is_loading = true;
        self.loading_message = message.to_string();
    }
    
    /// Stop loading indicator
    pub fn stop_loading(&mut self) {
        self.is_loading = false;
        self.loading_message.clear();
    }
    
    /// Fetch metagraph for current netuid
    pub fn fetch_metagraph(&mut self) {
        let netuid = self.current_netuid;
        let tx = self.async_tx.clone();
        let ctx = Arc::clone(&self.ctx);
        
        self.start_loading(&format!("Loading metagraph for subnet {}...", netuid));
        
        tokio::spawn(async move {
            let result = fetch_metagraph_data(&ctx, netuid).await;
            let _ = tx.send(AsyncResult::MetagraphLoaded { netuid, neurons: result }).await;
        });
    }
    
    /// Fetch subnets
    pub fn fetch_subnets(&mut self) {
        let tx = self.async_tx.clone();
        let ctx = Arc::clone(&self.ctx);
        
        self.start_loading("Loading subnets...");
        
        tokio::spawn(async move {
            let result = fetch_subnet_data(&ctx).await;
            let _ = tx.send(AsyncResult::SubnetsLoaded(result)).await;
        });
    }
    
    /// Fetch wallet balance
    pub fn fetch_balance(&mut self, wallet_idx: usize) {
        if wallet_idx >= self.wallets.len() {
            return;
        }
        
        let wallet = self.wallets[wallet_idx].clone();
        let tx = self.async_tx.clone();
        let ctx = Arc::clone(&self.ctx);
        
        self.start_loading(&format!("Fetching balance for {}...", wallet.name));
        
        tokio::spawn(async move {
            let result = fetch_wallet_balance(&ctx, &wallet).await;
            let _ = tx.send(AsyncResult::BalanceLoaded { wallet_idx, balance: result }).await;
        });
    }
    
    /// Fetch all wallet balances in parallel (batched for performance)
    pub fn fetch_all_balances(&mut self) {
        if self.wallets.is_empty() {
            return;
        }
        
        let wallets: Vec<_> = self.wallets.iter().cloned().enumerate().collect();
        let tx = self.async_tx.clone();
        let ctx = Arc::clone(&self.ctx);
        let count = wallets.len();
        
        self.add_message_sync(format!("⏳ Fetching {} wallet balances...", count));
        
        // Spawn parallel fetches for all wallets
        tokio::spawn(async move {
            use futures::future::join_all;
            
            let futures: Vec<_> = wallets.into_iter().map(|(idx, wallet)| {
                let ctx = Arc::clone(&ctx);
                let tx = tx.clone();
                async move {
                    let result = fetch_wallet_balance(&ctx, &wallet).await;
                    let _ = tx.send(AsyncResult::BalanceLoaded { wallet_idx: idx, balance: result }).await;
                }
            }).collect();
            
            join_all(futures).await;
            let _ = tx.send(AsyncResult::Message(format!("✓ Loaded {} balances", count))).await;
        });
    }
    
    /// Sync version of add_message for use in non-async context
    fn add_message_sync(&self, msg: String) {
        let messages = self.messages.clone();
        tokio::spawn(async move {
            messages.lock().await.push(msg);
        });
    }
    
    /// Fetch all wallet stakes in parallel
    pub fn fetch_all_stakes(&mut self) {
        if self.wallets.is_empty() {
            return;
        }
        
        let wallets: Vec<_> = self.wallets.iter().cloned().enumerate().collect();
        let tx = self.async_tx.clone();
        let ctx = Arc::clone(&self.ctx);
        
        // Spawn parallel fetches for all wallets
        tokio::spawn(async move {
            use futures::future::join_all;
            
            let futures: Vec<_> = wallets.into_iter().map(|(idx, wallet)| {
                let ctx = Arc::clone(&ctx);
                let tx = tx.clone();
                async move {
                    let result = fetch_wallet_stakes(&ctx, &wallet).await;
                    let _ = tx.send(AsyncResult::StakeLoaded { wallet_idx: idx, stakes: result }).await;
                }
            }).collect();
            
            join_all(futures).await;
        });
    }
}

/// Load wallets from directory
fn load_wallets(wallet_dir: &std::path::PathBuf) -> Vec<WalletInfo> {
    let mut wallets = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(wallet_dir) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    let wallet_name = entry.file_name().to_string_lossy().into_owned();
                    let wallet_path = entry.path();
                    
                    // Load coldkey address from coldkeypub.txt
                    let coldkey_address = load_coldkey_address(&wallet_path);
                    
                    // Load hotkeys
                    let hotkeys_path = wallet_path.join("hotkeys");
                    let hotkeys = if hotkeys_path.exists() {
                        std::fs::read_dir(&hotkeys_path)
                            .ok()
                            .map(|entries| {
                                entries
                                    .flatten()
                                    .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                                    .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    
                    wallets.push(WalletInfo {
                        name: wallet_name,
                        path: wallet_path,
                        coldkey_address,
                        hotkeys,
                    });
                }
            }
        }
    }
    
    wallets.sort_by(|a, b| a.name.cmp(&b.name));
    wallets
}

/// Load coldkey SS58 address from coldkeypub.txt
fn load_coldkey_address(wallet_path: &std::path::Path) -> Option<String> {
    let coldkeypub_path = wallet_path.join("coldkeypub.txt");
    if !coldkeypub_path.exists() {
        return None;
    }
    
    let content = std::fs::read_to_string(&coldkeypub_path).ok()?;
    
    // Parse JSON to extract ss58Address
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
        json.get("ss58Address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        // Fallback: treat as plain address
        Some(content.trim().to_string())
    }
}

/// Fetch metagraph data from network
async fn fetch_metagraph_data(ctx: &AppContext, netuid: u16) -> Result<Vec<NeuronDisplay>> {
    let service = ctx.require_service().await?;
    let metagraph = service.get_metagraph(netuid).await?;
    
    let discovery = NeuronDiscovery::new(&metagraph);
    let neurons = discovery.get_all_neurons()
        .map_err(|e| crate::errors::Error::network(&format!("Failed to discover neurons: {}", e)))?;
    
    let displays: Vec<NeuronDisplay> = neurons.into_iter().map(|n| {
        NeuronDisplay {
            uid: n.uid,
            hotkey: truncate_address(&n.hotkey, 8),
            coldkey: truncate_address(&n.coldkey, 8),
            stake: n.stake as f64 / 1_000_000_000.0, // Convert from rao to TAO
            is_validator: n.is_validator,
            ip: n.axon_info.as_ref().map(|a| a.ip.clone()).unwrap_or_default(),
            port: n.axon_info.as_ref().map(|a| a.port).unwrap_or(0),
            incentive: 0.0, // TODO: Extract from metagraph when available
            emission: 0.0,
            trust: 0.0,
            consensus: 0.0,
            dividends: 0.0,
        }
    }).collect();
    
    Ok(displays)
}

/// Fetch all subnet data from network in a single RPC call (FAST)
async fn fetch_subnet_data(ctx: &AppContext) -> Result<Vec<DynamicSubnetInfo>> {
    let service = ctx.require_service().await?;
    let client = service.client().await?;
    
    // Single RPC call to get ALL subnet data with DTAO pricing
    let subnets = bittensor_rs::queries::get_all_dynamic_info(&client).await
        .map_err(|e| crate::errors::Error::network(&format!("Failed to get dynamic info: {}", e)))?;
    
    Ok(subnets)
}

/// Fetch wallet balance from chain
async fn fetch_wallet_balance(ctx: &AppContext, wallet: &WalletInfo) -> Result<f64> {
    let address = wallet.coldkey_address.as_ref()
        .ok_or_else(|| crate::errors::Error::wallet("No coldkey address found"))?;
    
    let service = ctx.require_service().await?;
    let client = service.client().await?;
    
    let balance = bittensor_rs::queries::get_balance(&client, &address).await
        .map_err(|e| crate::errors::Error::network(&format!("Failed to get balance: {}", e)))?;
    
    Ok(balance.as_tao())
}

/// Fetch wallet stakes from chain
async fn fetch_wallet_stakes(ctx: &AppContext, wallet: &WalletInfo) -> Result<Vec<WalletStakeInfo>> {
    let address = match wallet.coldkey_address.as_ref() {
        Some(addr) => addr,
        None => return Ok(Vec::new()),
    };
    
    let service = ctx.require_service().await?;
    let client = service.client().await?;
    
    let stake_infos = bittensor_rs::queries::get_stake_info_for_coldkey(&client, address).await
        .map_err(|e| crate::errors::Error::network(&format!("Failed to get stakes: {}", e)))?;
    
    let stakes: Vec<WalletStakeInfo> = stake_infos.into_iter().map(|info| {
        WalletStakeInfo {
            netuid: info.netuid,
            hotkey: format!("{}", info.hotkey),
            stake_tao: info.stake.as_tao(),
            emission_tao: info.emission.as_tao(),
        }
    }).collect();
    
    Ok(stakes)
}

/// Truncate address for display
fn truncate_address(addr: &str, len: usize) -> String {
    if addr.len() <= len * 2 + 3 {
        addr.to_string()
    } else {
        format!("{}...{}", &addr[..len], &addr[addr.len()-len..])
    }
}

