//! # Data Table Component
//!
//! Reusable data table with cyberpunk styling, headers, and scrolling.

use crate::tui::theme::{colors, symbols};
use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

/// Data table component with distinctive styling
pub struct DataTable<'a> {
    pub title: &'a str,
    pub headers: Vec<&'a str>,
    pub rows: Vec<Vec<String>>,
    pub widths: Vec<Constraint>,
    pub state: &'a mut TableState,
    pub row_styles: Option<Vec<Style>>,
}

impl<'a> DataTable<'a> {
    pub fn new(
        title: &'a str,
        headers: Vec<&'a str>,
        rows: Vec<Vec<String>>,
        widths: Vec<Constraint>,
        state: &'a mut TableState,
    ) -> Self {
        Self {
            title,
            headers,
            rows,
            widths,
            state,
            row_styles: None,
        }
    }

    /// Set custom styles for each row
    pub fn with_row_styles(mut self, styles: Vec<Style>) -> Self {
        self.row_styles = Some(styles);
        self
    }

    pub fn render(&mut self, f: &mut Frame, area: Rect) {
        // Header with distinctive styling
        let header_cells = self.headers.iter().map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(colors::VOLT)
                    .add_modifier(Modifier::BOLD),
            )
        });

        let header = Row::new(header_cells)
            .style(Style::default().bg(colors::BG_HIGHLIGHT))
            .height(1)
            .bottom_margin(0);

        // Rows with alternating background and optional custom styles
        let rows = self.rows.iter().enumerate().map(|(i, row)| {
            let cells = row.iter().map(|c| Cell::from(c.as_str()));

            let base_style = if i % 2 == 0 {
                Style::default().bg(colors::BG_PANEL)
            } else {
                Style::default().bg(colors::BG_DEEP)
            };

            let style = self
                .row_styles
                .as_ref()
                .and_then(|styles| styles.get(i))
                .map(|s| base_style.patch(*s))
                .unwrap_or(base_style);

            Row::new(cells).style(style).height(1)
        });

        // Title with icon
        let title = format!("{} {} ", symbols::DIAMOND, self.title);

        let table = Table::new(rows, &self.widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(ratatui::widgets::BorderType::Rounded)
                    .border_style(Style::default().fg(colors::TEXT_TERTIARY))
                    .title(Span::styled(
                        title,
                        Style::default()
                            .fg(colors::VOLT)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .style(Style::default().bg(colors::BG_DEEP)),
            )
            .highlight_style(
                Style::default()
                    .bg(colors::BG_SELECTED)
                    .fg(colors::LIGHTNING)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▸ ");

        f.render_stateful_widget(table, area, self.state);
    }
}

/// Styled cell helper for creating cells with specific formatting
pub struct StyledCell;

impl StyledCell {
    /// Create a cell with TAO amount styling
    pub fn tao(amount: f64) -> Cell<'static> {
        let text = if amount >= 1_000_000.0 {
            format!("{:.2}M {}", amount / 1_000_000.0, symbols::TAO)
        } else if amount >= 1_000.0 {
            format!("{:.2}K {}", amount / 1_000.0, symbols::TAO)
        } else if amount >= 1.0 {
            format!("{:.2} {}", amount, symbols::TAO)
        } else if amount > 0.0 {
            format!("{:.4} {}", amount, symbols::TAO)
        } else {
            format!("0 {}", symbols::TAO)
        };

        Cell::from(text).style(Style::default().fg(colors::TAO))
    }

    /// Create a cell with percentage styling (color based on value)
    pub fn percentage(value: f64) -> Cell<'static> {
        let style = if value >= 10.0 {
            Style::default().fg(colors::SUCCESS)
        } else if value >= 5.0 {
            Style::default().fg(colors::WARNING)
        } else if value > 0.0 {
            Style::default().fg(colors::TEXT_SECONDARY)
        } else {
            Style::default().fg(colors::TEXT_TERTIARY)
        };

        Cell::from(format!("{:.2}%", value)).style(style)
    }

    /// Create a cell with address styling (truncated)
    pub fn address(addr: &str) -> Cell<'static> {
        let truncated = if addr.len() > 16 {
            format!("{}…{}", &addr[..8], &addr[addr.len() - 6..])
        } else {
            addr.to_string()
        };

        Cell::from(truncated).style(Style::default().fg(colors::TEXT_ACCENT))
    }

    /// Create a cell with status indicator
    pub fn status(is_active: bool) -> Cell<'static> {
        if is_active {
            Cell::from(symbols::CONNECTED).style(Style::default().fg(colors::SUCCESS))
        } else {
            Cell::from(symbols::DISCONNECTED).style(Style::default().fg(colors::TEXT_TERTIARY))
        }
    }

    /// Create a cell with validator/miner indicator
    pub fn role(is_validator: bool) -> Cell<'static> {
        if is_validator {
            Cell::from("V").style(
                Style::default()
                    .fg(colors::VALIDATOR)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Cell::from("M").style(Style::default().fg(colors::MINER))
        }
    }
}
