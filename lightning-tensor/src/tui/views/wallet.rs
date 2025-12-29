//! # Wallet View
//!
//! Wallet management view with cyberpunk styling.

use crate::tui::app::App;
use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
    Frame,
};

/// Draw the wallet view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
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
                    .fg(colors::VOLT)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(colors::LIGHTNING)
            } else {
                Style::default().fg(colors::TEXT_PRIMARY)
            };

            let marker = if is_active {
                symbols::CONNECTED
            } else {
                symbols::DISCONNECTED
            };

            // Show balance if available
            let balance_str = app
                .wallet_balances
                .get(i)
                .and_then(|b| *b)
                .map(|b| format!(" [{:.2}{}]", b, symbols::TAO))
                .unwrap_or_default();

            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", marker), style),
                Span::styled(&wallet.name, style),
                Span::styled(balance_str, Style::default().fg(colors::TAO)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} Wallets ({}) ", symbols::DIAMOND, app.wallets.len()),
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_DEEP)),
        )
        .highlight_style(
            Style::default()
                .bg(colors::BG_SELECTED)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

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
            let balance = app
                .wallet_balances
                .get(idx)
                .and_then(|b| *b)
                .map(|b| format!("{:.4} {}", b, symbols::TAO))
                .unwrap_or_else(|| "Loading...".to_string());

            let addr = wallet.coldkey_address.as_deref().unwrap_or("N/A");
            let short_addr = if addr.len() > 16 {
                format!("{}…{}", &addr[..8], &addr[addr.len() - 8..])
            } else {
                addr.to_string()
            };

            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Name: ", Style::default().fg(colors::TEXT_SECONDARY)),
                    Span::styled(
                        &wallet.name,
                        Style::default()
                            .fg(colors::TEXT_PRIMARY)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Address: ", Style::default().fg(colors::TEXT_SECONDARY)),
                    Span::styled(short_addr, Style::default().fg(colors::TEXT_ACCENT)),
                ]),
                Line::from(vec![
                    Span::styled("  Balance: ", Style::default().fg(colors::TEXT_SECONDARY)),
                    Span::styled(
                        balance,
                        Style::default()
                            .fg(colors::TAO)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Hotkeys: ", Style::default().fg(colors::TEXT_SECONDARY)),
                    Span::styled(
                        format!("{}", wallet.hotkeys.len()),
                        Style::default().fg(colors::LIGHTNING),
                    ),
                    Span::styled(
                        format!(" ({})", wallet.hotkeys.join(", ")),
                        Style::default().fg(colors::TEXT_TERTIARY),
                    ),
                ]),
            ]
        } else {
            vec![Line::from("Wallet not found")]
        }
    } else {
        vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "  No wallet selected",
                Style::default().fg(colors::TEXT_TERTIARY),
            )]),
            Line::from(vec![Span::styled(
                "  Use ↑/↓ to navigate",
                Style::default().fg(colors::TEXT_TERTIARY),
            )]),
        ]
    };

    let details = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(colors::TEXT_TERTIARY))
            .title(Span::styled(
                format!(" {} Wallet Info ", symbols::INFO),
                Style::default()
                    .fg(colors::INFO)
                    .add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(colors::BG_PANEL)),
    );

    f.render_widget(details, chunks[0]);

    // Stakes table
    draw_stakes_table(f, app, chunks[1]);

    // Footer
    let footer = Line::from(vec![
        Span::styled("↑/↓ ", Style::default().fg(colors::VOLT)),
        Span::styled("Navigate  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Enter ", Style::default().fg(colors::VOLT)),
        Span::styled("Select  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("b ", Style::default().fg(colors::VOLT)),
        Span::styled("Balance  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("B ", Style::default().fg(colors::VOLT)),
        Span::styled(
            "All Balances  ",
            Style::default().fg(colors::TEXT_SECONDARY),
        ),
        Span::styled("Esc ", Style::default().fg(colors::VOLT)),
        Span::styled("Back", Style::default().fg(colors::TEXT_SECONDARY)),
    ]);

    f.render_widget(Paragraph::new(footer), chunks[2]);
}

fn draw_stakes_table(f: &mut Frame, app: &App, area: Rect) {
    let stakes = app
        .wallet_list_state
        .selected()
        .and_then(|idx| app.wallet_stakes.get(idx))
        .cloned()
        .unwrap_or_default();

    if stakes.is_empty() {
        let msg = if app.is_connected {
            "No stakes found (or loading...)"
        } else {
            "Connect to view stakes"
        };
        let paragraph = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                msg,
                Style::default().fg(colors::TEXT_TERTIARY),
            )]),
        ])
        .alignment(ratatui::layout::Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} Alpha Stakes ", symbols::ALPHA),
                    Style::default()
                        .fg(colors::ALPHA)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_DEEP)),
        );
        f.render_widget(paragraph, area);
        return;
    }

    // Calculate total stake
    let total_stake: f64 = stakes.iter().map(|s| s.stake_tao).sum();

    let header_cells = ["Subnet", "Hotkey", "Stake", "Emission"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(colors::VOLT)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells)
        .style(Style::default().bg(colors::BG_HIGHLIGHT))
        .height(1);

    let rows = stakes.iter().enumerate().map(|(i, stake)| {
        let base_style = if i % 2 == 0 {
            Style::default().bg(colors::BG_PANEL)
        } else {
            Style::default().bg(colors::BG_DEEP)
        };

        let cells = vec![
            Cell::from(format!("{}", stake.netuid)).style(Style::default().fg(colors::LIGHTNING)),
            Cell::from(truncate(&stake.hotkey, 12)).style(Style::default().fg(colors::TEXT_ACCENT)),
            Cell::from(format!("{:.4} {}", stake.stake_tao, symbols::ALPHA))
                .style(Style::default().fg(colors::ALPHA)),
            Cell::from(format!("{:.6} {}", stake.emission_tao, symbols::TAO))
                .style(Style::default().fg(colors::SUCCESS)),
        ];
        Row::new(cells).style(base_style).height(1)
    });

    let widths = [
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(14),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(colors::TEXT_TERTIARY))
            .title(Span::styled(
                format!(
                    " {} Alpha Stakes (Total: {:.4} {}) ",
                    symbols::ALPHA,
                    total_stake,
                    symbols::ALPHA
                ),
                Style::default()
                    .fg(colors::ALPHA)
                    .add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(colors::BG_DEEP)),
    );

    f.render_widget(table, area);
}

fn truncate(s: &str, len: usize) -> String {
    if s.len() <= len {
        s.to_string()
    } else {
        format!("{}…", &s[..len - 1])
    }
}
