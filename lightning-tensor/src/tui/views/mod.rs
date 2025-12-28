//! # TUI Views
//!
//! Feature-specific views for the TUI.

mod home;
mod wallet;
mod stake;
mod subnet;
mod metagraph;

use crate::tui::app::{App, AppState};
use crate::tui::components::InputField;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Main draw function - dispatches to appropriate view
pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),   // Header
            Constraint::Min(0),      // Main content
            Constraint::Length(3),   // Status bar
        ])
        .split(f.size());

    // Draw header
    draw_header(f, app, chunks[0]);

    // Draw main content based on state
    match app.state {
        AppState::Home => home::draw(f, app, chunks[1]),
        AppState::Wallet => wallet::draw(f, app, chunks[1]),
        AppState::Stake => stake::draw(f, app, chunks[1]),
        AppState::Subnet => subnet::draw(f, app, chunks[1]),
        AppState::Metagraph => metagraph::draw(f, app, chunks[1]),
        AppState::Transfer => draw_placeholder(f, "Transfer", chunks[1]),
        AppState::Weights => draw_placeholder(f, "Weights", chunks[1]),
        AppState::Root => draw_placeholder(f, "Root Network", chunks[1]),
    }

    // Draw status bar
    draw_status_bar(f, app, chunks[2]);

    // Draw input overlay if in input mode
    if app.input_mode {
        draw_input_overlay(f, app, f.size());
    }
}

/// Draw the header
fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let network = app.ctx.network_name();
    let title = format!("⚡ Lightning Tensor │ {}", network);
    
    let header = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    
    f.render_widget(header, area);
}

/// Draw the status bar
fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let state_name = match app.state {
        AppState::Home => "Home",
        AppState::Wallet => "Wallet",
        AppState::Stake => "Stake",
        AppState::Subnet => "Subnets",
        AppState::Metagraph => "Metagraph",
        AppState::Transfer => "Transfer",
        AppState::Weights => "Weights",
        AppState::Root => "Root",
    };
    
    let help_text = match app.state {
        AppState::Home => "w:Wallet s:Stake n:Subnets m:Metagraph t:Transfer c:Connect q:Quit",
        AppState::Wallet => "↑↓:Navigate Enter:Select b:Balance B:All Esc:Back",
        AppState::Stake => "a:Add r:Remove Esc:Back",
        AppState::Subnet => "↑↓:Navigate Enter:Metagraph r:Refresh Esc:Back",
        AppState::Metagraph => "↑↓:Navigate PgUp/Dn:Page r:Refresh Esc:Back",
        AppState::Transfer => "t:Transfer Esc:Back",
        AppState::Weights => "s:Set Esc:Back",
        AppState::Root => "r:Register Esc:Back",
    };
    
    let loading = if app.is_loading { " ⟳" } else { "" };
    
    let status = Line::from(vec![
        Span::styled(
            format!(" {} ", state_name),
            Style::default().fg(Color::Black).bg(Color::Yellow),
        ),
        Span::raw(" │ "),
        Span::styled(help_text, Style::default().fg(Color::Gray)),
        Span::styled(loading, Style::default().fg(Color::Yellow)),
    ]);
    
    let status_bar = Paragraph::new(status)
        .block(Block::default().borders(Borders::ALL));
    
    f.render_widget(status_bar, area);
}

/// Draw input overlay
fn draw_input_overlay(f: &mut Frame, app: &App, area: Rect) {
    // Create a centered input box
    let input_area = centered_rect(60, 15, area);
    
    // Clear background
    f.render_widget(ratatui::widgets::Clear, input_area);
    
    let input = InputField::new(&app.input_prompt, &app.input_buffer)
        .password(app.is_password_input)
        .focused(true);
    
    input.render(f, input_area);
}

/// Draw placeholder for unimplemented views
fn draw_placeholder(f: &mut Frame, title: &str, area: Rect) {
    let text = format!("{} view - Coming soon!", title);
    let placeholder = Paragraph::new(text)
        .style(Style::default().fg(Color::Gray))
        .alignment(ratatui::layout::Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title),
        );
    
    f.render_widget(placeholder, area);
}

/// Create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

