//! # TUI Views
//!
//! Feature-specific views for the TUI with cyberpunk styling.

mod home;
mod metagraph;
mod root;
mod stake;
mod subnet;
mod transfer;
mod wallet;
mod weights;

use crate::tui::app::{App, AppState};
use crate::tui::components::InputField;
use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
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
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Status bar
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
        AppState::Transfer => transfer::draw(f, app, chunks[1]),
        AppState::Weights => weights::draw(f, app, chunks[1]),
        AppState::Root => root::draw(f, app, chunks[1]),
    }

    // Draw status bar
    draw_status_bar(f, app, chunks[2]);

    // Draw input overlay if in input mode
    if app.input_mode {
        draw_input_overlay(f, app, f.size());
    }
}

/// Draw the header with cyberpunk styling
fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let network = app.ctx.network_name();
    let lightning = app.animation_state.lightning_pulse();

    let title_spans = vec![
        Span::styled(lightning, Style::default().fg(colors::VOLT)),
        Span::styled(" ", Style::default()),
        Span::styled(
            "LIGHTNING",
            Style::default()
                .fg(colors::LIGHTNING)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " TENSOR",
            Style::default()
                .fg(colors::PLASMA)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", symbols::VERTICAL),
            Style::default().fg(colors::TEXT_TERTIARY),
        ),
        Span::styled(network, Style::default().fg(colors::TEXT_ACCENT)),
        Span::styled(" ", Style::default()),
        Span::styled(lightning, Style::default().fg(colors::VOLT)),
    ];

    let header = Paragraph::new(Line::from(title_spans))
        .alignment(ratatui::layout::Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::VOLT))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

    f.render_widget(header, area);
}

/// Draw the status bar
fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let state_name = match app.state {
        AppState::Home => "HOME",
        AppState::Wallet => "WALLET",
        AppState::Stake => "STAKE",
        AppState::Subnet => "SUBNETS",
        AppState::Metagraph => "METAGRAPH",
        AppState::Transfer => "TRANSFER",
        AppState::Weights => "WEIGHTS",
        AppState::Root => "ROOT",
    };

    let help_text = match app.state {
        AppState::Home => "w:Wallet s:Stake n:Subnets m:Metagraph t:Transfer c:Connect q:Quit",
        AppState::Wallet => "↑↓:Navigate Enter:Select b:Balance B:All Esc:Back",
        AppState::Stake => "a:Add r:Remove Esc:Back",
        AppState::Subnet => "↑↓:Navigate Enter:Metagraph r:Refresh Esc:Back",
        AppState::Metagraph => "↑↓:Navigate PgUp/Dn:Page r:Refresh Esc:Back",
        AppState::Transfer => "d:Dest a:Amount Enter:Send Esc:Back",
        AppState::Weights => "u:UIDs w:Weights Enter:Submit Esc:Back",
        AppState::Root => "r:Register v:Validators F5:Refresh Esc:Back",
    };

    // Connection status
    let (conn_icon, conn_text) = app.animation_state.connection_indicator(app.is_connected);
    let conn_color = if app.is_connected {
        colors::SUCCESS
    } else {
        colors::ERROR
    };

    let loading = if app.is_loading {
        vec![
            Span::styled(" ", Style::default()),
            Span::styled(
                app.animation_state.spinner_char().to_string(),
                Style::default().fg(colors::LIGHTNING),
            ),
        ]
    } else {
        vec![]
    };

    let mut status_spans = vec![
        Span::styled(
            format!(" {} ", state_name),
            Style::default()
                .fg(colors::BG_DEEP)
                .bg(colors::VOLT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", symbols::VERTICAL),
            Style::default().fg(colors::TEXT_TERTIARY),
        ),
        Span::styled(conn_icon, Style::default().fg(conn_color)),
        Span::styled(
            format!(" {} ", conn_text),
            Style::default().fg(colors::TEXT_TERTIARY),
        ),
        Span::styled(
            format!("{} ", symbols::VERTICAL),
            Style::default().fg(colors::TEXT_TERTIARY),
        ),
        Span::styled(help_text, Style::default().fg(colors::TEXT_SECONDARY)),
    ];

    status_spans.extend(loading);

    let status_bar = Paragraph::new(Line::from(status_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(colors::TEXT_TERTIARY))
            .style(Style::default().bg(colors::BG_PANEL)),
    );

    f.render_widget(status_bar, area);
}

/// Draw input overlay with cyberpunk styling
fn draw_input_overlay(f: &mut Frame, app: &App, area: Rect) {
    // Create a centered input box
    let input_area = centered_rect(60, 20, area);

    // Clear background
    f.render_widget(ratatui::widgets::Clear, input_area);

    let input = InputField::new(&app.input_prompt, &app.input_buffer)
        .password(app.is_password_input)
        .focused(true);

    input.render(f, input_area);
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
