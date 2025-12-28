//! # Spinner Component
//!
//! Loading spinner animation.

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    widgets::Paragraph,
    Frame,
};
use super::AnimationState;

/// Spinner component
pub struct Spinner<'a> {
    pub message: &'a str,
    pub animation: &'a AnimationState,
}

impl<'a> Spinner<'a> {
    pub fn new(message: &'a str, animation: &'a AnimationState) -> Self {
        Self { message, animation }
    }
    
    pub fn render(&self, f: &mut Frame, area: Rect) {
        let spinner_char = self.animation.spinner_char();
        let text = format!("{} {}", spinner_char, self.message);
        
        let widget = Paragraph::new(text)
            .style(Style::default().fg(Color::Yellow));
        
        f.render_widget(widget, area);
    }
}

