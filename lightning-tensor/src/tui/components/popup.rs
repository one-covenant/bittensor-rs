//! # Popup Component
//!
//! Modal popup for confirmations and messages with cyberpunk styling.

use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

/// Popup type determines styling
#[derive(Clone, Copy)]
pub enum PopupType {
    Info,
    Warning,
    Error,
    Confirm,
    Loading,
}

/// Popup component with distinctive styling
pub struct Popup<'a> {
    pub title: &'a str,
    pub message: &'a str,
    pub popup_type: PopupType,
    pub buttons: Option<Vec<&'a str>>,
    pub selected_button: usize,
}

impl<'a> Popup<'a> {
    pub fn info(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Info,
            buttons: None,
            selected_button: 0,
        }
    }

    pub fn warning(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Warning,
            buttons: None,
            selected_button: 0,
        }
    }

    pub fn error(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Error,
            buttons: None,
            selected_button: 0,
        }
    }

    pub fn confirm(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Confirm,
            buttons: Some(vec!["Cancel", "Confirm"]),
            selected_button: 1,
        }
    }

    pub fn loading(title: &'a str, message: &'a str) -> Self {
        Self {
            title,
            message,
            popup_type: PopupType::Loading,
            buttons: None,
            selected_button: 0,
        }
    }

    pub fn with_buttons(mut self, buttons: Vec<&'a str>) -> Self {
        self.buttons = Some(buttons);
        self
    }

    pub fn select_button(mut self, idx: usize) -> Self {
        self.selected_button = idx;
        self
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        // Center the popup
        let popup_area = centered_rect(60, 40, area);

        // Get type-specific styling
        let (border_color, icon, bg_color) = match self.popup_type {
            PopupType::Info => (colors::INFO, symbols::INFO, colors::BG_PANEL),
            PopupType::Warning => (colors::WARNING, symbols::WARNING, colors::BG_PANEL),
            PopupType::Error => (colors::ERROR, symbols::ERROR, colors::BG_PANEL),
            PopupType::Confirm => (colors::SUCCESS, symbols::DIAMOND, colors::BG_PANEL),
            PopupType::Loading => (colors::LIGHTNING, symbols::LOADING, colors::BG_PANEL),
        };

        // Clear the background
        f.render_widget(Clear, popup_area);

        // Title with icon
        let title = format!(" {} {} ", icon, self.title);

        let block = Block::default()
            .title(Span::styled(
                title,
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(border_color))
            .style(Style::default().bg(bg_color));

        let inner_area = block.inner(popup_area);
        f.render_widget(block, popup_area);

        // Layout for content and buttons
        let has_buttons = self.buttons.is_some() && !self.buttons.as_ref().unwrap().is_empty();
        let chunks = if has_buttons {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(inner_area)
        } else {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0)])
                .split(inner_area)
        };

        // Message content
        let content = Paragraph::new(self.message)
            .style(Style::default().fg(colors::TEXT_PRIMARY))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });

        f.render_widget(content, chunks[0]);

        // Render buttons if present
        if has_buttons {
            let buttons = self.buttons.as_ref().unwrap();
            let button_spans: Vec<Span> = buttons
                .iter()
                .enumerate()
                .flat_map(|(i, btn)| {
                    let is_selected = i == self.selected_button;
                    let style = if is_selected {
                        Style::default()
                            .fg(colors::BG_DEEP)
                            .bg(border_color)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(colors::TEXT_SECONDARY)
                    };

                    vec![Span::styled(format!(" {} ", btn), style), Span::raw("  ")]
                })
                .collect();

            let buttons_line = Line::from(button_spans);
            let buttons_widget = Paragraph::new(buttons_line).alignment(Alignment::Center);

            f.render_widget(buttons_widget, chunks[1]);
        }
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
