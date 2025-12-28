//! # Metagraph View
//!
//! Subnet metagraph visualization for the TUI with a rich table display.

use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Scrollbar, ScrollbarOrientation, ScrollbarState},
    Frame,
};

/// Draw the metagraph view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header info
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
    
    let validator_count = app.metagraph_neurons.iter().filter(|n| n.is_validator).count();
    let miner_count = neuron_count - validator_count;
    
    let header_text = vec![
        Line::from(vec![
            Span::styled("Subnet: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", netuid),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  │  "),
            Span::styled("Neurons: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", neuron_count),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("  │  "),
            Span::styled("Validators: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", validator_count),
                Style::default().fg(Color::Green),
            ),
            Span::raw("  │  "),
            Span::styled("Miners: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", miner_count),
                Style::default().fg(Color::Magenta),
            ),
        ]),
    ];

    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::BOTTOM));

    f.render_widget(header, area);
}

fn draw_table(f: &mut Frame, app: &mut App, area: Rect) {
    if app.metagraph_neurons.is_empty() {
        let loading_msg = if app.is_loading {
            format!("⟳ {}", app.loading_message)
        } else {
            "No neurons loaded. Press [r] to refresh.".to_string()
        };
        
        let empty = Paragraph::new(loading_msg)
            .style(Style::default().fg(Color::Gray))
            .alignment(ratatui::layout::Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Metagraph"),
            );
        f.render_widget(empty, area);
        return;
    }

    // Table header
    let header_cells = ["UID", "Type", "Hotkey", "Coldkey", "Stake (τ)", "IP", "Port"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .style(Style::default())
        .height(1);

    // Table rows
    let rows = app.metagraph_neurons.iter().enumerate().map(|(idx, neuron)| {
        let selected = app.metagraph_table_state.selected() == Some(idx);
        let style = if selected {
            Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
        } else if neuron.is_validator {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::White)
        };

        let type_icon = if neuron.is_validator { "V" } else { "M" };
        let type_color = if neuron.is_validator { Color::Green } else { Color::Magenta };

        let cells = vec![
            Cell::from(format!("{:>4}", neuron.uid)),
            Cell::from(type_icon).style(Style::default().fg(type_color)),
            Cell::from(neuron.hotkey.clone()),
            Cell::from(neuron.coldkey.clone()),
            Cell::from(format!("{:>10.4}", neuron.stake)),
            Cell::from(if neuron.ip.is_empty() { "—".to_string() } else { neuron.ip.clone() }),
            Cell::from(if neuron.port == 0 { "—".to_string() } else { neuron.port.to_string() }),
        ];

        Row::new(cells).style(style).height(1)
    });

    let widths = [
        Constraint::Length(5),   // UID
        Constraint::Length(4),   // Type
        Constraint::Length(18),  // Hotkey
        Constraint::Length(18),  // Coldkey
        Constraint::Length(12),  // Stake
        Constraint::Length(15),  // IP
        Constraint::Length(6),   // Port
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("⚡ Metagraph - Subnet {}", app.current_netuid))
                .title_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");

    // Render table with scroll state
    f.render_stateful_widget(table, area, &mut app.metagraph_table_state);

    // Add scrollbar if there are many neurons
    if app.metagraph_neurons.len() > 10 {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        
        let mut scrollbar_state = ScrollbarState::new(app.metagraph_neurons.len())
            .position(app.metagraph_table_state.selected().unwrap_or(0));
        
        f.render_stateful_widget(
            scrollbar,
            area.inner(ratatui::layout::Margin { horizontal: 0, vertical: 1 }),
            &mut scrollbar_state,
        );
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let selected = app.metagraph_table_state.selected().unwrap_or(0);
    let total = app.metagraph_neurons.len();
    
    let footer_text = Line::from(vec![
        Span::styled("↑/↓ ", Style::default().fg(Color::Yellow)),
        Span::raw("Navigate  "),
        Span::styled("PgUp/PgDn ", Style::default().fg(Color::Yellow)),
        Span::raw("Page  "),
        Span::styled("Home/End ", Style::default().fg(Color::Yellow)),
        Span::raw("Jump  "),
        Span::styled("r ", Style::default().fg(Color::Yellow)),
        Span::raw("Refresh  "),
        Span::styled("Esc ", Style::default().fg(Color::Yellow)),
        Span::raw("Back  "),
        Span::raw("│  "),
        Span::styled(
            format!("{}/{}", selected + 1, total),
            Style::default().fg(Color::Cyan),
        ),
    ]);

    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Gray));

    f.render_widget(footer, area);
}
