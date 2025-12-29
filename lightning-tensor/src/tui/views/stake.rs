//! # Stake View
//!
//! Staking management view with cyberpunk styling.

use crate::tui::app::App;
use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Draw the stake view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(65),
        ])
        .split(area);

    // Draw stake summary
    draw_stake_summary(f, app, chunks[0]);

    // Draw stake positions
    draw_stake_positions(f, app, chunks[1]);
}

fn draw_stake_summary(f: &mut Frame, app: &App, area: Rect) {
    let wallet_name = app
        .selected_wallet_info()
        .map(|w| w.name.as_str())
        .unwrap_or("No wallet selected");

    let balance = app
        .selected_wallet_balance()
        .map(|b| format!("{:.4} {}", b, symbols::TAO))
        .unwrap_or_else(|| "—".to_string());

    let content = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Wallet: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                wallet_name,
                Style::default()
                    .fg(colors::VOLT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Available: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(balance, Style::default().fg(colors::TAO)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("{}─────────────────────────────────{}", symbols::DIAMOND, symbols::DIAMOND),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Actions:",
                Style::default()
                    .fg(colors::TEXT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("    [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("a", Style::default().fg(colors::SUCCESS).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Add stake", Style::default().fg(colors::TEXT_PRIMARY)),
            Span::styled("      [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("r", Style::default().fg(colors::ERROR).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Remove stake", Style::default().fg(colors::TEXT_PRIMARY)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("    [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("l", Style::default().fg(colors::LIGHTNING).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("List positions", Style::default().fg(colors::TEXT_PRIMARY)),
            Span::styled("   [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("m", Style::default().fg(colors::PLASMA).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Move stake", Style::default().fg(colors::TEXT_PRIMARY)),
        ]),
    ];

    let summary = Paragraph::new(content)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} Stake Management ", symbols::LIGHTNING),
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

    f.render_widget(summary, area);
}

fn draw_stake_positions(f: &mut Frame, app: &App, area: Rect) {
    // Get stakes if wallet is selected
    let stakes = app
        .selected_wallet
        .and_then(|idx| app.wallet_stakes.get(idx))
        .cloned()
        .unwrap_or_default();

    let content = if stakes.is_empty() {
        if app.is_loading {
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        format!("  {} ", app.animation_state.spinner_char()),
                        Style::default().fg(colors::LIGHTNING),
                    ),
                    Span::styled("Loading stake positions...", Style::default().fg(colors::TEXT_SECONDARY)),
                ]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "  No stake positions loaded",
                    Style::default().fg(colors::TEXT_TERTIARY),
                )]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "  Press [l] to load stake positions",
                    Style::default().fg(colors::TEXT_SECONDARY),
                )]),
            ]
        }
    } else {
        // Calculate total stake
        let total_stake: f64 = stakes.iter().map(|s| s.stake_tao).sum();
        let total_emission: f64 = stakes.iter().map(|s| s.emission_tao).sum();

        let mut lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Total Staked: ", Style::default().fg(colors::TEXT_SECONDARY)),
                Span::styled(
                    format!("{:.4} {}", total_stake, symbols::ALPHA),
                    Style::default().fg(colors::ALPHA).add_modifier(Modifier::BOLD),
                ),
                Span::styled("    Emission: ", Style::default().fg(colors::TEXT_SECONDARY)),
                Span::styled(
                    format!("{:.6} {}/day", total_emission * 7200.0, symbols::TAO),
                    Style::default().fg(colors::SUCCESS),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  {}─────────────────────────────────────────────────{}", symbols::DIAMOND, symbols::DIAMOND),
                    Style::default().fg(colors::TEXT_TERTIARY),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{:<8} {:<14} {:>14} {:>14}", "Subnet", "Hotkey", "Stake", "Emission"),
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
        ];

        for stake in stakes.iter().take(10) {
            let hotkey_short = if stake.hotkey.len() > 12 {
                format!("{}…", &stake.hotkey[..11])
            } else {
                stake.hotkey.clone()
            };

            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{:<8}", stake.netuid),
                    Style::default().fg(colors::LIGHTNING),
                ),
                Span::styled(
                    format!("{:<14}", hotkey_short),
                    Style::default().fg(colors::TEXT_ACCENT),
                ),
                Span::styled(
                    format!("{:>12.4} {}", stake.stake_tao, symbols::ALPHA),
                    Style::default().fg(colors::ALPHA),
                ),
                Span::styled(
                    format!("{:>12.6} {}", stake.emission_tao, symbols::TAO),
                    Style::default().fg(colors::SUCCESS),
                ),
            ]));
        }

        if stakes.len() > 10 {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                format!("  ... and {} more positions", stakes.len() - 10),
                Style::default().fg(colors::TEXT_TERTIARY),
            )]));
        }

        lines
    };

    let positions = Paragraph::new(content)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} Stake Positions ", symbols::ALPHA),
                    Style::default()
                        .fg(colors::ALPHA)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_DEEP)),
        );

    f.render_widget(positions, area);
}
