//! # Transfer View
//!
//! TAO transfer interface with cyberpunk styling.
//! Allows sending TAO between wallets with visual feedback.

use crate::tui::app::App;
use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Draw the transfer view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Header with balance
            Constraint::Length(8),  // Transfer form
            Constraint::Min(5),     // Recent transfers / status
            Constraint::Length(2),  // Footer
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_transfer_form(f, app, chunks[1]);
    draw_status_panel(f, app, chunks[2]);
    draw_footer(f, chunks[3]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let wallet_info = if let Some(wallet) = app.selected_wallet_info() {
        let balance = app.selected_wallet_balance().unwrap_or(0.0);
        vec![
            Line::from(vec![
                Span::styled(
                    format!("{} ", symbols::LIGHTNING),
                    Style::default().fg(colors::VOLT),
                ),
                Span::styled(
                    "Transfer TAO",
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("From: ", Style::default().fg(colors::TEXT_SECONDARY)),
                Span::styled(
                    &wallet.name,
                    Style::default()
                        .fg(colors::LIGHTNING)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled("Balance: ", Style::default().fg(colors::TEXT_SECONDARY)),
                Span::styled(
                    format!("{:.4} {}", balance, symbols::TAO),
                    Style::default().fg(colors::TAO),
                ),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled(
                    format!("{} ", symbols::WARNING),
                    Style::default().fg(colors::WARNING),
                ),
                Span::styled(
                    "No wallet selected",
                    Style::default().fg(colors::WARNING),
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Press [w] to select a wallet first",
                Style::default().fg(colors::TEXT_SECONDARY),
            )]),
        ]
    };

    let header = Paragraph::new(wallet_info)
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

    f.render_widget(header, area);
}

fn draw_transfer_form(f: &mut Frame, app: &App, area: Rect) {
    let form_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2), // Destination
            Constraint::Length(2), // Amount
            Constraint::Length(2), // Action hint
        ])
        .split(area);

    // Destination field
    let dest_display = if app.transfer_dest.is_empty() {
        Span::styled(
            "Press [d] to enter destination address",
            Style::default().fg(colors::TEXT_TERTIARY),
        )
    } else {
        Span::styled(&app.transfer_dest, Style::default().fg(colors::TEXT_ACCENT))
    };

    let dest_line = Line::from(vec![
        Span::styled(
            format!("{} To: ", symbols::ARROW_RIGHT),
            Style::default()
                .fg(colors::LIGHTNING)
                .add_modifier(Modifier::BOLD),
        ),
        dest_display,
    ]);

    f.render_widget(Paragraph::new(dest_line), form_chunks[0]);

    // Amount field
    let amount_display = if app.transfer_amount.is_empty() {
        Span::styled(
            "Press [a] to enter amount",
            Style::default().fg(colors::TEXT_TERTIARY),
        )
    } else {
        Span::styled(
            format!("{} {}", app.transfer_amount, symbols::TAO),
            Style::default().fg(colors::TAO),
        )
    };

    let amount_line = Line::from(vec![
        Span::styled(
            format!("{} Amount: ", symbols::DIAMOND),
            Style::default()
                .fg(colors::VOLT)
                .add_modifier(Modifier::BOLD),
        ),
        amount_display,
    ]);

    f.render_widget(Paragraph::new(amount_line), form_chunks[1]);

    // Action hint
    let can_transfer = !app.transfer_dest.is_empty()
        && !app.transfer_amount.is_empty()
        && app.selected_wallet.is_some();

    let action_hint = if can_transfer {
        Line::from(vec![
            Span::styled(
                format!("{} ", symbols::SUCCESS),
                Style::default().fg(colors::SUCCESS),
            ),
            Span::styled(
                "Press [Enter] to confirm transfer",
                Style::default().fg(colors::SUCCESS),
            ),
        ])
    } else {
        Line::from(vec![Span::styled(
            "Complete all fields to transfer",
            Style::default().fg(colors::TEXT_TERTIARY),
        )])
    };

    f.render_widget(Paragraph::new(action_hint), form_chunks[2]);

    // Form container
    let form_block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(colors::LIGHTNING_DIM))
        .title(Span::styled(
            format!(" {} Transfer Details ", symbols::DIAMOND),
            Style::default()
                .fg(colors::VOLT)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(colors::BG_DEEP));

    f.render_widget(form_block, area);
}

fn draw_status_panel(f: &mut Frame, app: &App, area: Rect) {
    // Network fee estimation and transaction info
    let content = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Network Fee: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("~0.0001 {}", symbols::TAO),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Finality: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled("~12 seconds", Style::default().fg(colors::TEXT_TERTIARY)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("  {} ", symbols::INFO),
                Style::default().fg(colors::INFO),
            ),
            Span::styled(
                "Transfers are irreversible. Double-check the address.",
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
        ]),
    ];

    let loading_content = if app.is_loading {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  {} ", app.animation_state.spinner_char()),
                    Style::default().fg(colors::LIGHTNING),
                ),
                Span::styled(
                    &app.loading_message,
                    Style::default().fg(colors::TEXT_SECONDARY),
                ),
            ]),
        ]
    } else {
        content
    };

    let status = Paragraph::new(loading_content)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} Status ", symbols::INFO),
                    Style::default().fg(colors::INFO),
                ))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

    f.render_widget(status, area);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Line::from(vec![
        Span::styled("d ", Style::default().fg(colors::VOLT)),
        Span::styled("Destination  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("a ", Style::default().fg(colors::VOLT)),
        Span::styled("Amount  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Enter ", Style::default().fg(colors::VOLT)),
        Span::styled("Send  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Esc ", Style::default().fg(colors::VOLT)),
        Span::styled("Back", Style::default().fg(colors::TEXT_SECONDARY)),
    ]);

    f.render_widget(Paragraph::new(footer), area);
}
