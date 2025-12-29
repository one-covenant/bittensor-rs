//! # Metagraph View
//!
//! Subnet metagraph visualization with cyberpunk styling and rich table display.

use crate::tui::app::App;
use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table,
    },
    Frame,
};

/// Draw the metagraph view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Header info
            Constraint::Min(0),    // Table
            Constraint::Length(2), // Footer with scroll info
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let netuid = app.current_netuid;
    let neuron_count = app.metagraph_neurons.len();

    let validator_count = app
        .metagraph_neurons
        .iter()
        .filter(|n| n.is_validator)
        .count();
    let miner_count = neuron_count - validator_count;

    // Calculate total stake
    let total_stake: f64 = app.metagraph_neurons.iter().map(|n| n.stake).sum();

    let header_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("Subnet: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("{}", netuid),
                Style::default()
                    .fg(colors::VOLT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}  ", symbols::VERTICAL),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
            Span::styled("Neurons: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("{}", neuron_count),
                Style::default().fg(colors::LIGHTNING),
            ),
            Span::styled(
                format!("  {}  ", symbols::VERTICAL),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
            Span::styled("V: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("{}", validator_count),
                Style::default().fg(colors::VALIDATOR),
            ),
            Span::styled("  M: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("{}", miner_count),
                Style::default().fg(colors::MINER),
            ),
            Span::styled(
                format!("  {}  ", symbols::VERTICAL),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
            Span::styled("Total Stake: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                format!("{:.2}K {}", total_stake / 1000.0, symbols::TAO),
                Style::default().fg(colors::TAO),
            ),
        ]),
    ];

    let header = Paragraph::new(header_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(colors::TEXT_TERTIARY)),
    );

    f.render_widget(header, area);
}

fn draw_table(f: &mut Frame, app: &mut App, area: Rect) {
    if app.metagraph_neurons.is_empty() {
        let loading_msg = if app.is_loading {
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
                    "No neurons loaded. Press [r] to refresh.",
                    Style::default().fg(colors::TEXT_TERTIARY),
                )]),
            ]
        };

        let empty = Paragraph::new(loading_msg)
            .alignment(ratatui::layout::Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(ratatui::widgets::BorderType::Rounded)
                    .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                    .title(Span::styled(
                        format!(" {} Metagraph ", symbols::LIGHTNING),
                        Style::default()
                            .fg(colors::VOLT)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .style(Style::default().bg(colors::BG_DEEP)),
            );
        f.render_widget(empty, area);
        return;
    }

    // Table header
    let header_cells = ["UID", "Role", "Hotkey", "Coldkey", "Stake", "IP", "Port"]
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

    // Table rows
    let rows = app
        .metagraph_neurons
        .iter()
        .enumerate()
        .map(|(idx, neuron)| {
            let selected = app.metagraph_table_state.selected() == Some(idx);
            let base_style = if idx % 2 == 0 {
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

            let (role_icon, role_color) = if neuron.is_validator {
                ("V", colors::VALIDATOR)
            } else {
                ("M", colors::MINER)
            };

            // Format stake with color based on amount
            let stake_style = if neuron.stake > 1000.0 {
                Style::default().fg(colors::STAKE_HIGH)
            } else if neuron.stake > 100.0 {
                Style::default().fg(colors::STAKE_MED)
            } else {
                Style::default().fg(colors::STAKE_LOW)
            };

            let cells = vec![
                Cell::from(format!("{:>4}", neuron.uid))
                    .style(Style::default().fg(colors::LIGHTNING)),
                Cell::from(role_icon)
                    .style(Style::default().fg(role_color).add_modifier(Modifier::BOLD)),
                Cell::from(truncate_key(&neuron.hotkey))
                    .style(Style::default().fg(colors::TEXT_ACCENT)),
                Cell::from(truncate_key(&neuron.coldkey))
                    .style(Style::default().fg(colors::TEXT_SECONDARY)),
                Cell::from(format!("{:>10.2}", neuron.stake)).style(stake_style),
                Cell::from(if neuron.ip.is_empty() {
                    symbols::DISCONNECTED.to_string()
                } else {
                    neuron.ip.clone()
                })
                .style(Style::default().fg(colors::TEXT_TERTIARY)),
                Cell::from(if neuron.port == 0 {
                    symbols::DISCONNECTED.to_string()
                } else {
                    neuron.port.to_string()
                })
                .style(Style::default().fg(colors::TEXT_TERTIARY)),
            ];

            Row::new(cells).style(style).height(1)
        });

    let widths = [
        Constraint::Length(5),  // UID
        Constraint::Length(4),  // Role
        Constraint::Length(16), // Hotkey
        Constraint::Length(16), // Coldkey
        Constraint::Length(12), // Stake
        Constraint::Length(15), // IP
        Constraint::Length(6),  // Port
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
                        " {} Metagraph - Subnet {} ",
                        symbols::LIGHTNING,
                        app.current_netuid
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

    // Render table with scroll state
    f.render_stateful_widget(table, area, &mut app.metagraph_table_state);

    // Add scrollbar if there are many neurons
    if app.metagraph_neurons.len() > 10 {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"))
            .track_symbol(Some("│"))
            .thumb_symbol("█");

        let mut scrollbar_state = ScrollbarState::new(app.metagraph_neurons.len())
            .position(app.metagraph_table_state.selected().unwrap_or(0));

        f.render_stateful_widget(
            scrollbar,
            area.inner(Margin {
                horizontal: 0,
                vertical: 1,
            }),
            &mut scrollbar_state,
        );
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let selected = app.metagraph_table_state.selected().unwrap_or(0);
    let total = app.metagraph_neurons.len();

    let footer = Line::from(vec![
        Span::styled("↑/↓ ", Style::default().fg(colors::VOLT)),
        Span::styled("Navigate  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("PgUp/Dn ", Style::default().fg(colors::VOLT)),
        Span::styled("Page  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Home/End ", Style::default().fg(colors::VOLT)),
        Span::styled("Jump  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("r ", Style::default().fg(colors::VOLT)),
        Span::styled("Refresh  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Esc ", Style::default().fg(colors::VOLT)),
        Span::styled("Back  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled(
            format!("{}  {}/{}", symbols::VERTICAL, selected + 1, total),
            Style::default().fg(colors::LIGHTNING),
        ),
    ]);

    f.render_widget(Paragraph::new(footer), area);
}

/// Truncate a key for display (show first and last chars)
fn truncate_key(key: &str) -> String {
    if key.len() <= 14 {
        key.to_string()
    } else {
        format!("{}…{}", &key[..6], &key[key.len() - 5..])
    }
}
