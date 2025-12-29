//! # Root Network View
//!
//! Root network visualization showing subnet hierarchy and staking.
//! Displays the root network structure with validators and emissions.

use crate::tui::app::App;
use crate::tui::components::GradientProgress;
use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Draw the root network view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Header with root info
            Constraint::Min(10),   // Subnet hierarchy visualization
            Constraint::Length(6), // Registration panel
            Constraint::Length(2), // Footer
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_subnet_hierarchy(f, app, chunks[1]);
    draw_registration_panel(f, app, chunks[2]);
    draw_footer(f, chunks[3]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    // Calculate root network stats
    let total_subnets = app.subnets.len();
    let total_stake: f64 = app
        .subnets
        .iter()
        .map(|s| s.tao_in as f64 / 1_000_000_000.0)
        .sum();

    let header_content = vec![
        Line::from(vec![
            Span::styled(
                format!("{} ", symbols::STAR),
                Style::default().fg(colors::TAO),
            ),
            Span::styled(
                "Root Network",
                Style::default()
                    .fg(colors::TAO)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" (Subnet 0)", Style::default().fg(colors::TEXT_SECONDARY)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Subnets: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("{}", total_subnets),
                Style::default()
                    .fg(colors::LIGHTNING)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  │  "),
            Span::styled(
                "Total TAO Staked: ",
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
            Span::styled(
                format!("{:.2}K {}", total_stake / 1000.0, symbols::TAO),
                Style::default().fg(colors::TAO),
            ),
            Span::raw("  │  "),
            Span::styled(
                "Root Validators: ",
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
            Span::styled(
                "64", // Placeholder - would come from root metagraph
                Style::default().fg(colors::VALIDATOR),
            ),
        ]),
    ];

    let header = Paragraph::new(header_content)
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TAO))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

    f.render_widget(header, area);
}

fn draw_subnet_hierarchy(f: &mut Frame, app: &App, area: Rect) {
    let inner = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(colors::TEXT_TERTIARY))
        .title(Span::styled(
            format!(" {} Subnet Emission Hierarchy ", symbols::DIAMOND),
            Style::default()
                .fg(colors::VOLT)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(colors::BG_DEEP));

    let inner_area = inner.inner(area);
    f.render_widget(inner, area);

    if app.subnets.is_empty() {
        let empty_msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "No subnets loaded. Press [n] to load subnets.",
                Style::default().fg(colors::TEXT_TERTIARY),
            )]),
        ])
        .alignment(Alignment::Center);

        f.render_widget(empty_msg, inner_area);
        return;
    }

    // Calculate total emission for percentage display
    let total_emission: u64 = app
        .subnets
        .iter()
        .filter(|s| s.netuid != 0)
        .map(|s| s.tao_in_emission)
        .sum();

    // Show subnet hierarchy as a tree with emission bars
    let display_count = (inner_area.height as usize).saturating_sub(2).min(12);
    let mut sorted_subnets: Vec<_> = app.subnets.iter().collect();
    sorted_subnets.sort_by(|a, b| b.tao_in_emission.cmp(&a.tao_in_emission));

    let mut lines = Vec::new();
    lines.push(Line::from(""));

    // Root node
    lines.push(Line::from(vec![
        Span::styled(
            format!("  {} ", symbols::STAR),
            Style::default().fg(colors::TAO),
        ),
        Span::styled(
            "ROOT",
            Style::default()
                .fg(colors::TAO)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " ── distributes emission to subnets",
            Style::default().fg(colors::TEXT_TERTIARY),
        ),
    ]));

    for (i, subnet) in sorted_subnets.iter().take(display_count).enumerate() {
        if subnet.netuid == 0 {
            continue; // Skip root
        }

        let emission_pct = if total_emission > 0 {
            (subnet.tao_in_emission as f64 / total_emission as f64) * 100.0
        } else {
            0.0
        };

        let bar = GradientProgress::new(emission_pct, 15).render();
        let is_last = i == display_count.saturating_sub(1);
        let branch = if is_last {
            symbols::BRANCH_END
        } else {
            symbols::BRANCH
        };

        // Determine color based on emission percentage
        let emission_color = if emission_pct > 5.0 {
            colors::SUCCESS
        } else if emission_pct > 1.0 {
            colors::WARNING
        } else {
            colors::TEXT_TERTIARY
        };

        let name = if subnet.name.len() > 16 {
            format!("{}…", &subnet.name[..15])
        } else {
            subnet.name.clone()
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!("  {} ", branch),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
            Span::styled(
                format!("{:>2}", subnet.netuid),
                Style::default().fg(colors::LIGHTNING),
            ),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(emission_color)),
            Span::raw(" "),
            Span::styled(
                format!("{:>5.1}%", emission_pct),
                Style::default().fg(emission_color),
            ),
            Span::raw("  "),
            Span::styled(name, Style::default().fg(colors::TEXT_SECONDARY)),
        ]));
    }

    f.render_widget(Paragraph::new(lines), inner_area);
}

fn draw_registration_panel(f: &mut Frame, app: &App, area: Rect) {
    let wallet_status = if let Some(wallet) = app.selected_wallet_info() {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  {} ", symbols::DIAMOND),
                    Style::default().fg(colors::VOLT),
                ),
                Span::styled("Wallet: ", Style::default().fg(colors::TEXT_SECONDARY)),
                Span::styled(
                    &wallet.name,
                    Style::default()
                        .fg(colors::LIGHTNING)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  {} ", symbols::INFO),
                    Style::default().fg(colors::INFO),
                ),
                Span::styled(
                    "Root registration requires 10,000+ TAO stake",
                    Style::default().fg(colors::TEXT_TERTIARY),
                ),
            ]),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  {} ", symbols::WARNING),
                    Style::default().fg(colors::WARNING),
                ),
                Span::styled(
                    "Select a wallet to register on root network",
                    Style::default().fg(colors::TEXT_SECONDARY),
                ),
            ]),
        ]
    };

    let panel = Paragraph::new(wallet_status)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} Root Registration ", symbols::STAR),
                    Style::default()
                        .fg(colors::TAO)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

    f.render_widget(panel, area);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Line::from(vec![
        Span::styled("r ", Style::default().fg(colors::VOLT)),
        Span::styled("Register  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("v ", Style::default().fg(colors::VOLT)),
        Span::styled(
            "View Validators  ",
            Style::default().fg(colors::TEXT_SECONDARY),
        ),
        Span::styled("F5 ", Style::default().fg(colors::VOLT)),
        Span::styled("Refresh  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Esc ", Style::default().fg(colors::VOLT)),
        Span::styled("Back", Style::default().fg(colors::TEXT_SECONDARY)),
    ]);

    f.render_widget(Paragraph::new(footer), area);
}
