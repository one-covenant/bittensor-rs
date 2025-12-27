//! # Popup Component
//!
//! Modal popup for confirmations and messages.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

/// Popup type
pub enum PopupType {
    Info,
    Warning,
    Error,
    Confirm,
}

/// Popup component
pub struct Popup<'a> {
    pub title: &'a str,
    pub message: &'a str,
    pub popup_type: PopupType,
}

impl<'a> Popup<'a> {
    pub fn info(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Info,
        }
    }
    
    pub fn warning(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Warning,
        }
    }
    
    pub fn error(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Error,
        }
    }
    
    pub fn confirm(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Confirm,
        }
    }
    
    pub fn render(&self, f: &mut Frame, area: Rect) {
        // Center the popup
        let popup_area = centered_rect(60, 40, area);
        
        let border_color = match self.popup_type {
            PopupType::Info => Color::Cyan,
            PopupType::Warning => Color::Yellow,
            PopupType::Error => Color::Red,
            PopupType::Confirm => Color::Green,
        };
        
        // Clear the background
        f.render_widget(Clear, popup_area);
        
        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .style(Style::default().bg(Color::Black));
        
        let inner_area = block.inner(popup_area);
        f.render_widget(block, popup_area);
        
        let content = Paragraph::new(self.message)
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        
        f.render_widget(content, inner_area);
    }
}

/// Create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

