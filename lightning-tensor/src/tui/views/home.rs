//! # Home View
//!
//! Main landing page for the TUI with animated network visualization
//! and cyberpunk aesthetic.

use crate::tui::app::App;
use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Draw the home view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(40),
            Constraint::Percentage(20),
        ])
        .split(area);

    // Draw ASCII art logo
    draw_logo(f, app, chunks[0]);

    // Draw menu
    draw_menu(f, app, chunks[1]);

    // Draw messages
    draw_messages(f, app, chunks[2]);
}

fn draw_logo(f: &mut Frame, app: &mut App, area: Rect) {
    app.animation_state.update();

    // Get animated network mesh
    let logo_lines = app.animation_state.network_logo();

    let mut styled_lines: Vec<Line> = Vec::new();

    // Add some padding at the top
    styled_lines.push(Line::from(""));

    for line in logo_lines {
        // Apply gradient coloring based on position
        let styled = Line::from(vec![Span::styled(
            line,
            Style::default().fg(colors::LIGHTNING),
        )]);
        styled_lines.push(styled);
    }

    // Add tagline below logo
    styled_lines.push(Line::from(""));
    styled_lines.push(Line::from(vec![
        Span::styled(
            "L I G H T N I N G",
            Style::default()
                .fg(colors::VOLT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            "T E N S O R",
            Style::default()
                .fg(colors::PLASMA)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    let logo_widget = Paragraph::new(styled_lines)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::NONE));

    f.render_widget(logo_widget, area);
}

fn draw_menu(f: &mut Frame, app: &App, area: Rect) {
    // Connection status with animation
    let (conn_icon, _) = app.animation_state.connection_indicator(app.is_connected);
    let conn_color = if app.is_connected {
        colors::SUCCESS
    } else {
        colors::ERROR
    };
    let conn_text = if app.is_connected {
        "Connected"
    } else {
        "Disconnected"
    };

    let menu_items = vec![
        Line::from(vec![
            Span::styled(
                format!("{} ", symbols::LIGHTNING),
                Style::default().fg(colors::VOLT),
            ),
            Span::styled(
                "Collective Intelligence at the Speed of Light",
                Style::default()
                    .fg(colors::TEXT_PRIMARY)
                    .add_modifier(Modifier::ITALIC),
            ),
            Span::styled(
                format!(" {}", symbols::LIGHTNING),
                Style::default().fg(colors::VOLT),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Network: ", Style::default().fg(colors::TEXT_SECONDARY)),
            Span::styled(
                app.ctx.network_name(),
                Style::default()
                    .fg(colors::LIGHTNING)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(conn_icon, Style::default().fg(conn_color)),
            Span::styled(
                format!(" {}", conn_text),
                Style::default().fg(conn_color),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("{}──────────────────────────────────{}", symbols::DIAMOND, symbols::DIAMOND),
                Style::default().fg(colors::TEXT_TERTIARY),
            ),
        ]),
        Line::from(""),
        // Navigation row 1
        Line::from(vec![
            Span::styled(" [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("w", Style::default().fg(colors::VOLT).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Wallet", Style::default().fg(colors::TEXT_PRIMARY)),
            Span::styled("     [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("s", Style::default().fg(colors::VOLT).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Stake", Style::default().fg(colors::TEXT_PRIMARY)),
            Span::styled("     [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("n", Style::default().fg(colors::VOLT).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Subnets", Style::default().fg(colors::TEXT_PRIMARY)),
        ]),
        Line::from(""),
        // Navigation row 2
        Line::from(vec![
            Span::styled(" [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("m", Style::default().fg(colors::VOLT).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Metagraph", Style::default().fg(colors::TEXT_PRIMARY)),
            Span::styled("   [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("t", Style::default().fg(colors::VOLT).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Transfer", Style::default().fg(colors::TEXT_PRIMARY)),
            Span::styled("  [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("g", Style::default().fg(colors::VOLT).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Weights", Style::default().fg(colors::TEXT_PRIMARY)),
        ]),
        Line::from(""),
        // Navigation row 3
        Line::from(vec![
            Span::styled(" [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("c", Style::default().fg(colors::LIGHTNING).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Connect", Style::default().fg(colors::LIGHTNING)),
            Span::styled("    [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("r", Style::default().fg(colors::TAO).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Root", Style::default().fg(colors::TAO)),
            Span::styled("      [ ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("q", Style::default().fg(colors::ERROR).add_modifier(Modifier::BOLD)),
            Span::styled(" ] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled("Quit", Style::default().fg(colors::ERROR)),
        ]),
    ];

    let menu = Paragraph::new(menu_items)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                .title(Span::styled(
                    format!(" {} Navigation ", symbols::DIAMOND),
                    Style::default()
                        .fg(colors::VOLT)
                        .add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

    f.render_widget(menu, area);
}

fn draw_messages(f: &mut Frame, app: &App, area: Rect) {
    // Get messages synchronously for rendering
    let messages_lines: Vec<Line> = if let Ok(messages) = app.messages.try_lock() {
        if messages.is_empty() {
            vec![Line::from(vec![Span::styled(
                "Ready.",
                Style::default().fg(colors::TEXT_TERTIARY),
            )])]
        } else {
            messages
                .iter()
                .rev()
                .take(4)
                .map(|msg| {
                    // Color-code messages based on content
                    let style = if msg.starts_with('✓') || msg.contains("Connected") {
                        Style::default().fg(colors::SUCCESS)
                    } else if msg.starts_with('✗') || msg.contains("failed") {
                        Style::default().fg(colors::ERROR)
                    } else if msg.starts_with('⏳') || msg.contains("Loading") {
                        Style::default().fg(colors::WARNING)
                    } else {
                        Style::default().fg(colors::TEXT_SECONDARY)
                    };
                    Line::from(vec![
                        Span::styled(format!(" {} ", symbols::CHEVRON_RIGHT), Style::default().fg(colors::TEXT_TERTIARY)),
                        Span::styled(msg.clone(), style),
                    ])
                })
                .collect()
        }
    } else {
        vec![Line::from(vec![Span::styled(
            "Loading...",
            Style::default().fg(colors::TEXT_TERTIARY),
        )])]
    };

    let messages_widget = Paragraph::new(messages_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(colors::TEXT_TERTIARY))
            .title(Span::styled(
                format!(" {} Messages ", symbols::INFO),
                Style::default().fg(colors::INFO),
            ))
            .style(Style::default().bg(colors::BG_PANEL)),
    );

    f.render_widget(messages_widget, area);
}
