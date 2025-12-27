//! # Wallet View
//!
//! Wallet management view for the TUI.

use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

/// Draw the wallet view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(area);

    // Draw wallet list
    draw_wallet_list(f, app, chunks[0]);
    
    // Draw wallet details
    draw_wallet_details(f, app, chunks[1]);
}

fn draw_wallet_list(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .wallets
        .iter()
        .enumerate()
        .map(|(i, wallet)| {
            let selected = app.selected_wallet == Some(i);
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            
            let marker = if selected { "◉ " } else { "○ " };
            ListItem::new(Line::from(vec![
                Span::styled(marker, style),
                Span::styled(&wallet.name, style),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Wallets"),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(list, area, &mut app.wallet_list_state);
}

fn draw_wallet_details(f: &mut Frame, app: &App, area: Rect) {
    let content = if let Some(idx) = app.selected_wallet {
        if let Some(wallet) = app.wallets.get(idx) {
            let coldkey = wallet.get_coldkey_ss58().unwrap_or_else(|_| "N/A".to_string());
            
            vec![
                Line::from(vec![
                    Span::styled("Name: ", Style::default().fg(Color::Gray)),
                    Span::styled(&wallet.name, Style::default().fg(Color::White)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Coldkey: ", Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::styled(
                        truncate_address(&coldkey),
                        Style::default().fg(Color::Cyan),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Path: ", Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::styled(
                        wallet.path.display().to_string(),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Actions:", Style::default().fg(Color::Yellow)),
                ]),
                Line::from(vec![
                    Span::styled("  [b] ", Style::default().fg(Color::Green)),
                    Span::raw("Check balance"),
                ]),
                Line::from(vec![
                    Span::styled("  [h] ", Style::default().fg(Color::Green)),
                    Span::raw("List hotkeys"),
                ]),
            ]
        } else {
            vec![Line::from("Wallet not found")]
        }
    } else {
        vec![
            Line::from(Span::styled(
                "No wallet selected",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from("Use ↑/↓ to navigate and Enter to select"),
        ]
    };

    let details = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Wallet Details"),
        );

    f.render_widget(details, area);
}

fn truncate_address(addr: &str) -> String {
    if addr.len() > 20 {
        format!("{}...{}", &addr[..10], &addr[addr.len()-8..])
    } else {
        addr.to_string()
    }
}

