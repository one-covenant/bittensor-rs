//! # Input Field Component
//!
//! Text input field with cyberpunk styling and optional password masking.

use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Input field component with distinctive styling
pub struct InputField<'a> {
    pub prompt: &'a str,
    pub value: &'a str,
    pub is_password: bool,
    pub is_focused: bool,
    pub placeholder: Option<&'a str>,
}

impl<'a> InputField<'a> {
    pub fn new(prompt: &'a str, value: &'a str) -> Self {
        Self {
            prompt,
            value,
            is_password: false,
            is_focused: false,
            placeholder: None,
        }
    }

    pub fn password(mut self, is_password: bool) -> Self {
        self.is_password = is_password;
        self
    }

    pub fn focused(mut self, is_focused: bool) -> Self {
        self.is_focused = is_focused;
        self
    }

    pub fn placeholder(mut self, text: &'a str) -> Self {
        self.placeholder = Some(text);
        self
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        let display_value = if self.is_password {
            symbols::BULLET.repeat(self.value.len())
        } else if self.value.is_empty() && self.placeholder.is_some() {
            self.placeholder.unwrap().to_string()
        } else {
            self.value.to_string()
        };

        let is_placeholder = self.value.is_empty() && self.placeholder.is_some();

        // Blinking cursor effect
        let cursor = if self.is_focused {
            Span::styled("█", Style::default().fg(colors::LIGHTNING))
        } else {
            Span::raw("")
        };

        let value_style = if is_placeholder {
            Style::default().fg(colors::TEXT_TERTIARY)
        } else if self.is_password {
            Style::default().fg(colors::WARNING)
        } else {
            Style::default().fg(colors::TEXT_PRIMARY)
        };

        let content = Line::from(vec![
            Span::styled(
                self.prompt,
                Style::default()
                    .fg(colors::LIGHTNING)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(display_value, value_style),
            cursor,
        ]);

        let (border_color, border_style) = if self.is_focused {
            (colors::LIGHTNING, Modifier::BOLD)
        } else {
            (colors::TEXT_TERTIARY, Modifier::empty())
        };

        // Title with icon
        let title = format!("{} Input", symbols::CHEVRON_RIGHT);

        let input = Paragraph::new(content).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color).add_modifier(border_style))
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(Span::styled(
                    title,
                    Style::default().fg(colors::VOLT).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors::BG_PANEL)),
        );

        f.render_widget(input, area);
    }
}
