//! # Stake View
//!
//! Staking management view for the TUI.

use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Draw the stake view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(70),
        ])
        .split(area);

    // Draw stake summary
    draw_stake_summary(f, app, chunks[0]);
    
    // Draw stake positions
    draw_stake_positions(f, app, chunks[1]);
}

fn draw_stake_summary(f: &mut Frame, app: &App, area: Rect) {
    let wallet_name = app.selected_wallet_info()
        .map(|w| w.name.as_str())
        .unwrap_or("No wallet selected");
    
    let content = vec![
        Line::from(vec![
            Span::styled("Wallet: ", Style::default().fg(Color::Gray)),
            Span::styled(wallet_name, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Actions:", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  [a] ", Style::default().fg(Color::Green)),
            Span::raw("Add stake"),
            Span::styled("  [r] ", Style::default().fg(Color::Red)),
            Span::raw("Remove stake"),
            Span::styled("  [l] ", Style::default().fg(Color::Cyan)),
            Span::raw("List positions"),
        ]),
    ];
    
    let summary = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Stake Summary"),
        );
    
    f.render_widget(summary, area);
}

fn draw_stake_positions(f: &mut Frame, _app: &App, area: Rect) {
    let content = vec![
        Line::from(Span::styled(
            "No stake positions loaded",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from("Press [l] to load stake positions"),
    ];
    
    let positions = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Stake Positions"),
        );
    
    f.render_widget(positions, area);
}

