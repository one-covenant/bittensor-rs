//! # Home View
//!
//! Main landing page for the TUI.

use crate::tui::app::App;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Draw the home view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(30),
            Constraint::Percentage(20),
        ])
        .split(area);

    // Draw ASCII art logo
    draw_logo(f, app, chunks[0]);
    
    // Draw menu
    draw_menu(f, chunks[1]);
    
    // Draw messages
    draw_messages(f, app, chunks[2]);
}

fn draw_logo(f: &mut Frame, app: &mut App, area: Rect) {
    app.animation_state.update();
    let node_char = app.animation_state.node_char();
    
    let logo = vec![
        format!("     {}───{}───{}     ", node_char, node_char, node_char),
        "    ╱ ╲ ╱ ╲ ╱ ╲    ".to_string(),
        format!("   {}───{}───{}───{}   ", node_char, node_char, node_char, node_char),
        "  ╱ ╲ ╱ ╲ ╱ ╲ ╱ ╲  ".to_string(),
        format!(" {}───{}───{}───{}───{} ", node_char, node_char, node_char, node_char, node_char),
        "  ╲ ╱ ╲ ╱ ╲ ╱ ╲ ╱  ".to_string(),
        format!("   {}───{}───{}───{}   ", node_char, node_char, node_char, node_char),
        "    ╲ ╱ ╲ ╱ ╲ ╱    ".to_string(),
        format!("     {}───{}───{}     ", node_char, node_char, node_char),
    ];
    
    let logo_text = logo.join("\n");
    
    let logo_widget = Paragraph::new(logo_text)
        .style(Style::default().fg(Color::Cyan))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::NONE));
    
    f.render_widget(logo_widget, area);
}

fn draw_menu(f: &mut Frame, area: Rect) {
    let menu_items = vec![
        Line::from(vec![
            Span::styled(
                "Collective Intelligence at the speed of ⚡",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("[ w ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Wallet"),
            Span::styled("   [ s ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Stake"),
            Span::styled("   [ n ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Subnets"),
        ]),
        Line::from(vec![
            Span::styled("[ t ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Transfer"),
            Span::styled(" [ g ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Weights"),
            Span::styled(" [ r ] ", Style::default().fg(Color::Yellow)),
            Span::raw("Root"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("[ q ] ", Style::default().fg(Color::Red)),
            Span::raw("Quit"),
        ]),
    ];
    
    let menu = Paragraph::new(menu_items)
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Menu"),
        );
    
    f.render_widget(menu, area);
}

fn draw_messages(f: &mut Frame, app: &App, area: Rect) {
    // We need to get messages synchronously for rendering
    // Using try_lock to avoid blocking
    let messages_text = if let Ok(messages) = app.messages.try_lock() {
        if messages.is_empty() {
            "No messages".to_string()
        } else {
            messages.iter().rev().take(5).cloned().collect::<Vec<_>>().join("\n")
        }
    } else {
        "Loading...".to_string()
    };
    
    let messages_widget = Paragraph::new(messages_text)
        .style(Style::default().fg(Color::Gray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Messages"),
        );
    
    f.render_widget(messages_widget, area);
}

