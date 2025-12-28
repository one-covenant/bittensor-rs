//! # Subnet View
//!
//! Subnet explorer view for the TUI.

use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

/// Draw the subnet view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    if app.subnets.is_empty() {
        draw_empty_state(f, area);
    } else {
        draw_subnet_table(f, app, area);
    }
}

fn draw_empty_state(f: &mut Frame, area: Rect) {
    let text = "Press [r] to load subnets";
    let paragraph = ratatui::widgets::Paragraph::new(text)
        .style(Style::default().fg(Color::Gray))
        .alignment(ratatui::layout::Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Subnets"),
        );
    
    f.render_widget(paragraph, area);
}

fn draw_subnet_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header_cells = ["NetUID", "Neurons", "Max", "Emission", "Tempo"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells)
        .style(Style::default())
        .height(1)
        .bottom_margin(1);

    let rows = app.subnets.iter().enumerate().map(|(i, subnet)| {
        let selected = app.selected_subnet == Some(i);
        let style = if selected {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        
        let cells = vec![
            Cell::from(subnet.netuid.to_string()),
            Cell::from(subnet.n.to_string()),
            Cell::from(subnet.max_n.to_string()),
            Cell::from("N/A".to_string()), // emission not available in SubnetInfo
            Cell::from(subnet.tempo.to_string()),
        ];
        Row::new(cells).style(style)
    });

    let widths = [
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Subnets ({} total)", app.subnets.len())),
        )
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::REVERSED)
                .fg(Color::Cyan),
        )
        .highlight_symbol("▸ ");

    // We don't have a proper TableState here, just render the table
    f.render_widget(table, area);
}

