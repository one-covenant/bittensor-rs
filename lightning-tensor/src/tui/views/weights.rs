//! # Weights View
//!
//! Subnet weights management interface with data visualization.
//! Allows validators to set weights on miners with visual feedback.

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

/// Draw the weights view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Header with subnet info
            Constraint::Min(10),    // Weight visualization
            Constraint::Length(6),  // Weight input form
            Constraint::Length(2),  // Footer
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_weight_visualization(f, app, chunks[1]);
    draw_weight_form(f, app, chunks[2]);
    draw_footer(f, chunks[3]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let subnet_info = format!("Subnet {}", app.current_netuid);
    let validator_status = if app.selected_wallet.is_some() {
        vec![
            Line::from(vec![
                Span::styled(
                    format!("{} ", symbols::LIGHTNING),
                    Style::default().fg(colors::VOLT),
                ),
                Span::styled(
                    "Set Weights",
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Subnet: ", Style::default().fg(colors::TEXT_SECONDARY)),
                Span::styled(
                    subnet_info,
                    Style::default()
                        .fg(colors::LIGHTNING)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled("Neurons: ", Style::default().fg(colors::TEXT_SECONDARY)),
                Span::styled(
                    format!("{}", app.metagraph_neurons.len()),
                    Style::default().fg(colors::INFO),
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
                "Select a validator wallet to set weights",
                Style::default().fg(colors::TEXT_SECONDARY),
            )]),
        ]
    };

    let header = Paragraph::new(validator_status)
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

fn draw_weight_visualization(f: &mut Frame, app: &App, area: Rect) {
    let inner = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(colors::PLASMA_DIM))
        .title(Span::styled(
            format!(" {} Weight Distribution ", symbols::DIAMOND),
            Style::default()
                .fg(colors::PLASMA)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(colors::BG_DEEP));

    let inner_area = inner.inner(area);
    f.render_widget(inner, area);

    // Show weight distribution as gradient bars
    if app.metagraph_neurons.is_empty() {
        let empty_msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "No neurons loaded. Press [n] to load subnets first.",
                Style::default().fg(colors::TEXT_TERTIARY),
            )]),
        ])
        .alignment(Alignment::Center);

        f.render_widget(empty_msg, inner_area);
        return;
    }

    // Show top neurons with visual weight bars
    let display_count = (inner_area.height as usize).saturating_sub(2).min(10);
    let top_neurons: Vec<_> = app
        .metagraph_neurons
        .iter()
        .take(display_count)
        .collect();

    let mut lines = Vec::new();
    lines.push(Line::from(""));

    for neuron in top_neurons {
        // Simulate weight as percentage (in real impl, this would come from actual weights)
        let weight_pct = if neuron.is_validator { 0.0 } else { 10.0 }; // Placeholder
        let bar = GradientProgress::new(weight_pct, 20).render();

        let role_indicator = if neuron.is_validator {
            Span::styled("V", Style::default().fg(colors::VALIDATOR).add_modifier(Modifier::BOLD))
        } else {
            Span::styled("M", Style::default().fg(colors::MINER))
        };

        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("{:>3}", neuron.uid),
                Style::default().fg(colors::LIGHTNING),
            ),
            Span::raw(" "),
            role_indicator,
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(colors::EMISSION_WARM)),
            Span::raw(" "),
            Span::styled(
                format!("{:.1}%", weight_pct),
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
            Span::raw("  "),
            Span::styled(
                &neuron.hotkey,
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
        ]));
    }

    f.render_widget(Paragraph::new(lines), inner_area);
}

fn draw_weight_form(f: &mut Frame, _app: &App, area: Rect) {
    let form_content = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("  {} ", symbols::ARROW_RIGHT),
                Style::default().fg(colors::VOLT),
            ),
            Span::styled("UIDs: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                "Enter comma-separated UIDs (e.g., 1,5,12,23)",
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("  {} ", symbols::DIAMOND),
                Style::default().fg(colors::VOLT),
            ),
            Span::styled("Weights: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                "Enter corresponding weights (e.g., 0.3,0.25,0.25,0.2)",
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
        ]),
        Line::from(""),
    ];

    let form = Paragraph::new(form_content)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} Set Weights ", symbols::LIGHTNING),
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

    f.render_widget(form, area);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Line::from(vec![
        Span::styled("u ", Style::default().fg(colors::VOLT)),
        Span::styled("Set UIDs  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("w ", Style::default().fg(colors::VOLT)),
        Span::styled("Set Weights  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Enter ", Style::default().fg(colors::VOLT)),
        Span::styled("Submit  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("r ", Style::default().fg(colors::VOLT)),
        Span::styled("Refresh  ", Style::default().fg(colors::TEXT_SECONDARY)),
        Span::styled("Esc ", Style::default().fg(colors::VOLT)),
        Span::styled("Back", Style::default().fg(colors::TEXT_SECONDARY)),
    ]);

    f.render_widget(Paragraph::new(footer), area);
}
