//! # Input Field Component
//!
//! Text input field with optional password masking.

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

/// Input field component
pub struct InputField<'a> {
    pub prompt: &'a str,
    pub value: &'a str,
    pub is_password: bool,
    pub is_focused: bool,
}

impl<'a> InputField<'a> {
    pub fn new(prompt: &'a str, value: &'a str) -> Self {
        Self {
            prompt,
            value,
            is_password: false,
            is_focused: false,
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
    
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let display_value = if self.is_password {
            "*".repeat(self.value.len())
        } else {
            self.value.to_string()
        };
        
        let cursor = if self.is_focused { "█" } else { "" };
        let text = format!("{}{}{}", self.prompt, display_value, cursor);
        
        let border_color = if self.is_focused {
            Color::Yellow
        } else {
            Color::Gray
        };
        
        let input = Paragraph::new(text)
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color))
                    .title("Input")
            );
        
        f.render_widget(input, area);
    }
}

