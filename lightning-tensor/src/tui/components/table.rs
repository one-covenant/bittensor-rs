//! # Data Table Component
//!
//! Reusable data table with headers and scrolling.

use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
    layout::Rect,
};

/// Data table component
pub struct DataTable<'a> {
    pub title: &'a str,
    pub headers: Vec<&'a str>,
    pub rows: Vec<Vec<String>>,
    pub widths: Vec<Constraint>,
    pub state: &'a mut TableState,
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
        }
    }
    
    pub fn render(&mut self, f: &mut Frame, area: Rect) {
        let header_cells = self.headers.iter().map(|h| {
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

        let rows = self.rows.iter().map(|row| {
            let cells = row.iter().map(|c| Cell::from(c.as_str()));
            Row::new(cells).height(1)
        });

        let table = Table::new(rows, &self.widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(self.title),
            )
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::REVERSED)
                    .fg(Color::Cyan),
            )
            .highlight_symbol("▸ ");

        f.render_stateful_widget(table, area, self.state);
    }
}

