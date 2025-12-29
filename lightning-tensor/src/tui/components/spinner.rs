//! # Spinner Component
//!
//! Loading spinner animations with cyberpunk styling.

use super::AnimationState;
use crate::tui::theme::colors;
use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

/// Spinner component with multiple styles
pub struct Spinner<'a> {
    pub message: &'a str,
    pub animation: &'a AnimationState,
    pub style: SpinnerStyle,
}

/// Spinner visual style
#[derive(Clone, Copy, Default)]
pub enum SpinnerStyle {
    #[default]
    Braille,
    Dots,
    Lightning,
    Bouncing,
}

impl<'a> Spinner<'a> {
    pub fn new(message: &'a str, animation: &'a AnimationState) -> Self {
        Self {
            message,
            animation,
            style: SpinnerStyle::default(),
        }
    }

    pub fn style(mut self, style: SpinnerStyle) -> Self {
        self.style = style;
        self
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        let (spinner_text, color) = match self.style {
            SpinnerStyle::Braille => (self.animation.spinner_char().to_string(), colors::LIGHTNING),
            SpinnerStyle::Dots => (self.animation.spinner_dots().to_string(), colors::PLASMA),
            SpinnerStyle::Lightning => (self.animation.lightning_pulse().to_string(), colors::VOLT),
            SpinnerStyle::Bouncing => (self.animation.bouncing_loader(8), colors::LIGHTNING),
        };

        let line = Line::from(vec![
            Span::styled(spinner_text, Style::default().fg(color)),
            Span::raw(" "),
            Span::styled(self.message, Style::default().fg(colors::TEXT_SECONDARY)),
        ]);

        let widget = Paragraph::new(line);
        f.render_widget(widget, area);
    }

    /// Render with a gradient loading bar
    pub fn render_with_bar(&self, f: &mut Frame, area: Rect, width: usize) {
        let bar = self.animation.loading_bar(width);

        let line = Line::from(vec![
            Span::styled("[", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled(bar, Style::default().fg(colors::LIGHTNING)),
            Span::styled("] ", Style::default().fg(colors::TEXT_TERTIARY)),
            Span::styled(self.message, Style::default().fg(colors::TEXT_SECONDARY)),
        ]);

        let widget = Paragraph::new(line);
        f.render_widget(widget, area);
    }
}

/// Inline loading indicator for status bars
pub struct LoadingIndicator<'a> {
    pub animation: &'a AnimationState,
}

impl<'a> LoadingIndicator<'a> {
    pub fn new(animation: &'a AnimationState) -> Self {
        Self { animation }
    }

    /// Get a simple spinning indicator
    pub fn spinner(&self) -> Span<'static> {
        Span::styled(
            self.animation.spinner_char().to_string(),
            Style::default().fg(colors::LIGHTNING),
        )
    }

    /// Get a pulsing lightning indicator
    pub fn pulse(&self) -> Span<'static> {
        Span::styled(
            self.animation.lightning_pulse().to_string(),
            Style::default().fg(colors::VOLT),
        )
    }

    /// Get connection status indicator
    pub fn connection(&self, connected: bool) -> (Span<'static>, Span<'static>) {
        let (icon, text) = self.animation.connection_indicator(connected);
        let color = if connected {
            colors::SUCCESS
        } else {
            colors::ERROR
        };

        (
            Span::styled(icon.to_string(), Style::default().fg(color)),
            Span::styled(
                format!(" {}", text),
                Style::default().fg(colors::TEXT_SECONDARY),
            ),
        )
    }
}
