//! # Wallet View
//!
//! Wallet management view for the TUI.

use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
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
            let selected = app.wallet_list_state.selected() == Some(i);
            let is_active = app.selected_wallet == Some(i);
            
            let style = if is_active {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            
            let marker = if is_active { "◉ " } else { "○ " };
            
            // Show balance if available
            let balance_str = app.wallet_balances.get(i)
                .and_then(|b| *b)
                .map(|b| format!(" [{:.2}τ]", b))
                .unwrap_or_default();
            
            ListItem::new(Line::from(vec![
                Span::styled(marker, style),
                Span::styled(&wallet.name, style),
                Span::styled(balance_str, Style::default().fg(Color::Green)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("⚡ Wallets ({})", app.wallets.len()))
                .title_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.wallet_list_state);
}

fn draw_wallet_details(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Basic info
            Constraint::Min(0),     // Stakes table
            Constraint::Length(2),  // Footer
        ])
        .split(area);

    // Basic wallet info
    let content = if let Some(idx) = app.wallet_list_state.selected() {
        if let Some(wallet) = app.wallets.get(idx) {
            let balance = app.wallet_balances.get(idx)
                .and_then(|b| *b)
                .map(|b| format!("{:.4} τ", b))
                .unwrap_or_else(|| "Loading...".to_string());
            
            let addr = wallet.coldkey_address.as_deref().unwrap_or("N/A");
            let short_addr = if addr.len() > 16 {
                format!("{}...{}", &addr[..8], &addr[addr.len()-8..])
            } else {
                addr.to_string()
            };
            
            vec![
                Line::from(vec![
                    Span::styled("Name: ", Style::default().fg(Color::Gray)),
                    Span::styled(&wallet.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("Address: ", Style::default().fg(Color::Gray)),
                    Span::styled(short_addr, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("Balance: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        balance,
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Hotkeys: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}", wallet.hotkeys.len()),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(
                        format!(" ({})", wallet.hotkeys.join(", ")),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
            ]
        } else {
            vec![Line::from("Wallet not found")]
        }
    } else {
        vec![
            Line::from(Span::styled("No wallet selected", Style::default().fg(Color::Gray))),
            Line::from("Use ↑/↓ to navigate"),
        ]
    };

    let details = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Wallet Info")
                .title_style(Style::default().fg(Color::Yellow)),
        );

    f.render_widget(details, chunks[0]);
    
    // Stakes table
    draw_stakes_table(f, app, chunks[1]);
    
    // Footer
    let footer = Line::from(vec![
        Span::styled("↑/↓ ", Style::default().fg(Color::Yellow)),
        Span::raw("Navigate  "),
        Span::styled("Enter ", Style::default().fg(Color::Yellow)),
        Span::raw("Select  "),
        Span::styled("b ", Style::default().fg(Color::Yellow)),
        Span::raw("Balance  "),
        Span::styled("Esc ", Style::default().fg(Color::Yellow)),
        Span::raw("Back"),
    ]);
    
    let footer_widget = Paragraph::new(footer)
        .style(Style::default().fg(Color::Gray));
    
    f.render_widget(footer_widget, chunks[2]);
}

fn draw_stakes_table(f: &mut Frame, app: &App, area: Rect) {
    let stakes = app.wallet_list_state.selected()
        .and_then(|idx| app.wallet_stakes.get(idx))
        .cloned()
        .unwrap_or_default();
    
    if stakes.is_empty() {
        let msg = if app.is_connected {
            "No stakes found (or loading...)"
        } else {
            "Connect to view stakes"
        };
        let paragraph = Paragraph::new(msg)
            .style(Style::default().fg(Color::Gray))
            .alignment(ratatui::layout::Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Alpha Stakes")
                    .title_style(Style::default().fg(Color::Yellow)),
            );
        f.render_widget(paragraph, area);
        return;
    }
    
    // Calculate total stake
    let total_stake: f64 = stakes.iter().map(|s| s.stake_tao).sum();
    
    let header_cells = ["Subnet", "Hotkey", "Stake (α)", "Emission"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells).height(1);

    let rows = stakes.iter().map(|stake| {
        let cells = vec![
            Cell::from(format!("{}", stake.netuid)).style(Style::default().fg(Color::Cyan)),
            Cell::from(truncate(&stake.hotkey, 12)),
            Cell::from(format!("{:.4}", stake.stake_tao)).style(Style::default().fg(Color::Magenta)),
            Cell::from(format!("{:.6}", stake.emission_tao)).style(Style::default().fg(Color::Green)),
        ];
        Row::new(cells).height(1)
    });

    let widths = [
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Length(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Alpha Stakes (Total: {:.4} α)", total_stake))
                .title_style(Style::default().fg(Color::Yellow)),
        );

    f.render_widget(table, area);
}

fn truncate(s: &str, len: usize) -> String {
    if s.len() <= len {
        s.to_string()
    } else {
        format!("{}…", &s[..len-1])
    }
}
