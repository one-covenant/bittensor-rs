//! # Subnet View
//!
//! Subnet explorer view for the TUI with cyberpunk styling.
//! Shows DTAO pricing, emission, name, and symbol for all subnets.

use crate::tui::app::App;
use crate::tui::components::GradientProgress;
use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

/// Draw the subnet view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Header
            Constraint::Min(0),    // Table
            Constraint::Length(2), // Footer
        ])
        .split(area);

    draw_header(f, app, chunks[0]);

    if app.subnets.is_empty() {
        draw_empty_state(f, app, chunks[1]);
    } else {
        draw_subnet_table(f, app, chunks[1]);
    }

    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    // Total TAO emission per block (excludes root)
    let total_tao_emission: u64 = app
        .subnets
        .iter()
        .filter(|s| s.netuid != 0)
        .map(|s| s.tao_in_emission)
        .sum();
    let total_tao = total_tao_emission as f64 / 1_000_000_000.0;

    // Sum of moving prices (for root sell flag: >1.0 means sell, ≤1.0 means recycle)
    let total_moving_price: f64 = app.subnets.iter().map(|s| s.moving_price).sum();
    let root_sell = total_moving_price > 1.0;

    let header_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("Subnets: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("{}", app.subnets.len()),
                Style::default()
                    .fg(colors::LIGHTNING)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}  ", symbols::VERTICAL),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
            Span::styled("Emission: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("{:.4} {}/blk", total_tao, symbols::TAO),
                Style::default().fg(colors::SUCCESS),
            ),
            Span::styled(
                format!("  {}  ", symbols::VERTICAL),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
            Span::styled("Root: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                if root_sell { "SELL" } else { "RECYCLE" },
                Style::default().fg(if root_sell {
                    colors::WARNING
                } else {
                    colors::PLASMA
                }),
            ),
            Span::styled(
                format!(" ({}={:.2})", symbols::ALPHA, total_moving_price),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
            if app.is_loading {
                Span::styled(
                    format!("  {} Loading...", app.animation_state.spinner_char()),
                    Style::default().fg(colors::LIGHTNING),
                )
            } else {
                Span::raw("")
            },
        ]),
    ];

    let header = Paragraph::new(header_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(colors::TEXT_TERTIARY)),
    );

    f.render_widget(header, area);
}

fn draw_empty_state(f: &mut Frame, app: &App, area: Rect) {
    let msg = if app.is_loading {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("{} ", app.animation_state.spinner_char()),
                    Style::default().fg(colors::LIGHTNING),
                ),
                Span::styled(
                    &app.loading_message,
                    Style::default().fg(colors::TEXT_SECONDARY),
                ),
            ]),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "No subnets loaded. Press [r] to fetch subnets.",
                Style::default().fg(colors::TEXT_TERTIARY),
            )]),
        ]
    };

    let paragraph = Paragraph::new(msg)
        .alignment(ratatui::layout::Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} DTAO Subnets ", symbols::LIGHTNING),
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_DEEP)),
        );

    f.render_widget(paragraph, area);
}

fn draw_subnet_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header_cells = ["#", "Name", "Price", "Emission", "Alpha Pool", "TAO Pool"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(colors::VOLT)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells)
        .style(Style::default().bg(colors::BG_HIGHLIGHT))
        .height(1);

    let selected_idx = app.subnet_list_state.selected();

    // Emission % is based on actual tao_in_emission
    let total_tao_emission: u64 = app
        .subnets
        .iter()
        .filter(|s| s.netuid != 0)
        .map(|s| s.tao_in_emission)
        .sum();

    let rows = app.subnets.iter().enumerate().map(|(i, subnet)| {
        let selected = selected_idx == Some(i);
        let base_style = if i % 2 == 0 {
            Style::default().bg(colors::BG_PANEL)
        } else {
            Style::default().bg(colors::BG_DEEP)
        };

        let style = if selected {
            Style::default()
                .bg(colors::BG_SELECTED)
                .add_modifier(Modifier::BOLD)
        } else {
            base_style
        };

        // Emission % based on actual TAO emission proportion
        let emission_pct = if total_tao_emission > 0 && subnet.netuid != 0 {
            (subnet.tao_in_emission as f64 / total_tao_emission as f64) * 100.0
        } else {
            0.0
        };

        // Format pools
        let alpha_in_tao = subnet.alpha_in as f64 / 1_000_000_000.0;
        let tao_in_tao = subnet.tao_in as f64 / 1_000_000_000.0;

        // Color price based on value
        let price_style = if subnet.price_tao > 1.0 {
            Style::default().fg(colors::SUCCESS)
        } else if subnet.price_tao > 0.1 {
            Style::default().fg(colors::WARNING)
        } else if subnet.price_tao > 0.0 {
            Style::default().fg(colors::TEXT_SECONDARY)
        } else {
            Style::default().fg(colors::TEXT_TERTIARY)
        };

        // Emission bar
        let emission_bar = GradientProgress::new(emission_pct * 2.0, 8).render();
        let emission_style = if emission_pct > 5.0 {
            colors::SUCCESS
        } else if emission_pct > 1.0 {
            colors::WARNING
        } else if emission_pct > 0.0 {
            colors::TEXT_SECONDARY
        } else {
            colors::TEXT_TERTIARY
        };

        let cells = vec![
            Cell::from(format!("{:>2}", subnet.netuid))
                .style(Style::default().fg(colors::LIGHTNING)),
            Cell::from(truncate_name(&subnet.name, 20)),
            Cell::from(format!("{:.4} {}", subnet.price_tao, symbols::TAO)).style(price_style),
            Cell::from(format!("{} {:>5.1}%", emission_bar, emission_pct))
                .style(Style::default().fg(emission_style)),
            Cell::from(format!(
                "{} {}",
                format_compact(alpha_in_tao),
                subnet.symbol
            ))
            .style(Style::default().fg(colors::ALPHA)),
            Cell::from(format!("{} {}", format_compact(tao_in_tao), symbols::TAO))
                .style(Style::default().fg(colors::TAO)),
        ];
        Row::new(cells).style(style).height(1)
    });

    let widths = [
        Constraint::Length(4),  // NetUID
        Constraint::Length(22), // Name
        Constraint::Length(12), // Price
        Constraint::Length(18), // Emission with bar
        Constraint::Length(14), // Alpha Pool
        Constraint::Length(12), // TAO Pool
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(
                        " {} DTAO Subnets ({} active) ",
                        symbols::LIGHTNING,
                        app.subnets.len()
                    ),
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_DEEP)),
        )
        .highlight_style(
            Style::default()
                .bg(colors::BG_SELECTED)
                .fg(colors::LIGHTNING)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.subnet_list_state);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let selected = app.subnet_list_state.selected().unwrap_or(0);
    let total = app.subnets.len();

    let footer = Line::from(vec![
        Span::styled("↑/↓ ", Style::default().fg(colors::VOLT)),
        Span::styled("Navigate  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Enter ", Style::default().fg(colors::VOLT)),
        Span::styled("Metagraph  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("r ", Style::default().fg(colors::VOLT)),
        Span::styled("Refresh  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Esc ", Style::default().fg(colors::VOLT)),
        Span::styled("Back  ", Style::default().fg(colors::TEXT_SECONDARY)),
        if total > 0 {
            Span::styled(
                format!("{}  {}/{}", symbols::VERTICAL, selected + 1, total),
                Style::default().fg(colors::LIGHTNING),
            )
        } else {
            Span::raw("")
        },
    ]);

    f.render_widget(Paragraph::new(footer), area);
}

/// Truncate name for display
fn truncate_name(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        format!("{}…", &name[..max_len - 1])
    }
}

/// Format large numbers compactly (K, M, etc)
fn format_compact(value: f64) -> String {
    if value >= 1_000_000.0 {
        format!("{:.1}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}K", value / 1_000.0)
    } else if value >= 1.0 {
        format!("{:.1}", value)
    } else if value > 0.0 {
        format!("{:.3}", value)
    } else {
        "0".to_string()
    }
}
