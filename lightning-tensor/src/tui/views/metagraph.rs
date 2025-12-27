//! # Metagraph View
//!
//! Subnet metagraph visualization for the TUI.

use crate::tui::app::App;
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Draw the metagraph view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let netuid = app.current_netuid;
    
    let content = vec![
        Line::from(vec![
            Span::styled("Subnet: ", Style::default().fg(Color::Gray)),
            Span::styled(
                netuid.to_string(),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Metagraph data not loaded",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from("Press [r] to refresh metagraph"),
    ];
    
    let paragraph = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Metagraph - Subnet {}", netuid)),
        );
    
    f.render_widget(paragraph, area);
}

