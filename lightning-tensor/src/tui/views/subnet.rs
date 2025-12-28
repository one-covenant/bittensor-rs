//! # Subnet View
//!
//! Subnet explorer view for the TUI.
//! Shows DTAO pricing, emission, name, and symbol for all subnets.

use crate::tui::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

/// Draw the subnet view
pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(0),     // Table
            Constraint::Length(2),  // Footer
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    
    if app.subnets.is_empty() {
        draw_empty_state(f, app, chunks[1]);
    } else {
        draw_subnet_table(f, app, chunks[1]);
    }
    
    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    // Total TAO emission per block (excludes root)
    let total_tao_emission: u64 = app.subnets.iter()
        .filter(|s| s.netuid != 0)
        .map(|s| s.tao_in_emission)
        .sum();
    let total_tao = total_tao_emission as f64 / 1_000_000_000.0;
    
    // Sum of moving prices (for root sell flag: >1.0 means sell, ≤1.0 means recycle)
    let total_moving_price: f64 = app.subnets.iter()
        .map(|s| s.moving_price)
        .sum();
    let root_sell = total_moving_price > 1.0;
    
    let header_text = vec![
        Line::from(vec![
            Span::styled("Subnets: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}", app.subnets.len()),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  │  "),
            Span::styled("Emission: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:.4} τ/blk", total_tao),
                Style::default().fg(Color::Green),
            ),
            Span::raw("  │  "),
            Span::styled("Root: ", Style::default().fg(Color::Gray)),
            Span::styled(
                if root_sell { "Sell" } else { "Recycle" },
                Style::default().fg(if root_sell { Color::Yellow } else { Color::Magenta }),
            ),
            Span::styled(
                format!(" (Σ={:.2})", total_moving_price),
                Style::default().fg(Color::DarkGray),
            ),
            if app.is_loading {
                Span::styled("  ⟳ Loading...", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("")
            },
        ]),
    ];

    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::BOTTOM));

    f.render_widget(header, area);
}

fn draw_empty_state(f: &mut Frame, app: &App, area: Rect) {
    let msg = if app.is_loading {
        format!("⟳ {}", app.loading_message)
    } else {
        "No subnets loaded. Press [r] to fetch subnets.".to_string()
    };
    
    let paragraph = Paragraph::new(msg)
        .style(Style::default().fg(Color::Gray))
        .alignment(ratatui::layout::Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("⚡ DTAO Subnets")
                .title_style(Style::default().fg(Color::Yellow)),
        );
    
    f.render_widget(paragraph, area);
}

fn draw_subnet_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header_cells = ["#", "Name", "Price (τ)", "Emission (%)", "Alpha Pool", "TAO Pool"]
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
        .height(1);

    let selected_idx = app.subnet_list_state.selected();
    
    // Emission % is based on actual tao_in_emission (result of TAO flow calculation)
    // This reflects the actual TAO distributed to each subnet
    // Note: Underlying calculation uses EMA of TAO flow (stake - unstake)
    let total_tao_emission: u64 = app.subnets.iter()
        .filter(|s| s.netuid != 0)
        .map(|s| s.tao_in_emission)
        .sum();
    
    let rows = app.subnets.iter().enumerate().map(|(i, subnet)| {
        let selected = selected_idx == Some(i);
        let style = if selected {
            Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        
        // Emission % based on actual TAO emission proportion
        let emission_pct = if total_tao_emission > 0 && subnet.netuid != 0 {
            (subnet.tao_in_emission as f64 / total_tao_emission as f64) * 100.0
        } else {
            0.0
        };
        
        // Format pools with symbol appended
        let alpha_in_tao = subnet.alpha_in as f64 / 1_000_000_000.0;
        let tao_in_tao = subnet.tao_in as f64 / 1_000_000_000.0;
        
        // Color price based on value
        let price_style = if subnet.price_tao > 1.0 {
            Style::default().fg(Color::Green)
        } else if subnet.price_tao > 0.1 {
            Style::default().fg(Color::Yellow)
        } else if subnet.price_tao > 0.0 {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        
        // Color emission based on percentage
        let emission_style = if emission_pct > 5.0 {
            Style::default().fg(Color::Green)
        } else if emission_pct > 1.0 {
            Style::default().fg(Color::Yellow)
        } else if emission_pct > 0.0 {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        
        let cells = vec![
            Cell::from(format!("{:>2}", subnet.netuid)).style(Style::default().fg(Color::Cyan)),
            Cell::from(truncate_name(&subnet.name, 24)),
            Cell::from(format!("{:.4}", subnet.price_tao)).style(price_style),
            Cell::from(format!("{:.2}%", emission_pct)).style(emission_style),
            // Alpha pool with symbol
            Cell::from(format!("{} {}", format_compact(alpha_in_tao), subnet.symbol))
                .style(Style::default().fg(Color::Magenta)),
            Cell::from(format!("{} τ", format_compact(tao_in_tao)))
                .style(Style::default().fg(Color::Yellow)),
        ];
        Row::new(cells).style(style).height(1)
    });

    let widths = [
        Constraint::Length(4),   // NetUID
        Constraint::Length(26),  // Name
        Constraint::Length(10),  // Price
        Constraint::Length(12),  // Emission
        Constraint::Length(14),  // Alpha Pool
        Constraint::Length(12),  // TAO Pool
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("⚡ DTAO Subnets ({} active)", app.subnets.len()))
                .title_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, &mut app.subnet_list_state);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let selected = app.subnet_list_state.selected().unwrap_or(0);
    let total = app.subnets.len();
    
    let footer_text = Line::from(vec![
        Span::styled("↑/↓ ", Style::default().fg(Color::Yellow)),
        Span::raw("Navigate  "),
        Span::styled("Enter ", Style::default().fg(Color::Yellow)),
        Span::raw("Metagraph  "),
        Span::styled("r ", Style::default().fg(Color::Yellow)),
        Span::raw("Refresh  "),
        Span::styled("Esc ", Style::default().fg(Color::Yellow)),
        Span::raw("Back  "),
        if total > 0 {
            Span::styled(
                format!("│  {}/{}", selected + 1, total),
                Style::default().fg(Color::Cyan),
            )
        } else {
            Span::raw("")
        },
    ]);

    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Gray));

    f.render_widget(footer, area);
}

/// Truncate name for display
fn truncate_name(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        format!("{}…", &name[..max_len - 1])
    }
}

/// Format large numbers compactly (K, M, etc)
fn format_compact(value: f64) -> String {
    if value >= 1_000_000.0 {
        format!("{:.2}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.2}K", value / 1_000.0)
    } else if value >= 1.0 {
        format!("{:.2}", value)
    } else if value > 0.0 {
        format!("{:.4}", value)
    } else {
        "0".to_string()
    }
}
