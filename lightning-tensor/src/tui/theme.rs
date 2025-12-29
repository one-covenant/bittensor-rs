//! # Theme Module
//!
//! Cohesive true-color palette and visual constants for a distinctive
//! cyberpunk/lightning aesthetic.

use ratatui::style::Style;

/// Lightning Tensor color palette - cyberpunk with electric accents
pub mod colors {
    use ratatui::style::Color;

    // Primary palette - Electric/Lightning theme
    pub const LIGHTNING: Color = Color::Rgb(0, 255, 255);      // #00ffff - Electric cyan
    pub const LIGHTNING_DIM: Color = Color::Rgb(0, 180, 180);  // Dimmed cyan
    pub const PLASMA: Color = Color::Rgb(255, 0, 255);         // #ff00ff - Hot magenta
    pub const PLASMA_DIM: Color = Color::Rgb(180, 0, 180);     // Dimmed magenta
    pub const VOLT: Color = Color::Rgb(255, 230, 0);           // #ffe600 - Electric yellow
    pub const VOLT_DIM: Color = Color::Rgb(180, 160, 0);       // Dimmed yellow

    // Background gradient colors
    pub const BG_DEEP: Color = Color::Rgb(10, 10, 20);         // #0a0a14 - Deep space
    pub const BG_PANEL: Color = Color::Rgb(20, 20, 35);        // #141423 - Panel bg
    pub const BG_HIGHLIGHT: Color = Color::Rgb(30, 30, 50);    // #1e1e32 - Highlight bg
    pub const BG_SELECTED: Color = Color::Rgb(40, 40, 70);     // #282846 - Selected row

    // Semantic colors
    pub const SUCCESS: Color = Color::Rgb(0, 255, 136);        // #00ff88 - Neon green
    pub const WARNING: Color = Color::Rgb(255, 170, 0);        // #ffaa00 - Amber
    pub const ERROR: Color = Color::Rgb(255, 60, 100);         // #ff3c64 - Hot pink/red
    pub const INFO: Color = Color::Rgb(100, 200, 255);         // #64c8ff - Sky blue

    // Text hierarchy
    pub const TEXT_PRIMARY: Color = Color::Rgb(240, 240, 250); // #f0f0fa - Bright white
    pub const TEXT_SECONDARY: Color = Color::Rgb(160, 160, 180); // #a0a0b4 - Muted
    pub const TEXT_TERTIARY: Color = Color::Rgb(100, 100, 120); // #646478 - Dim
    pub const TEXT_ACCENT: Color = Color::Rgb(180, 140, 255);  // #b48cff - Purple accent

    // Data visualization
    pub const STAKE_HIGH: Color = Color::Rgb(0, 255, 200);     // #00ffc8 - Teal
    pub const STAKE_MED: Color = Color::Rgb(100, 200, 150);    // #64c896
    pub const STAKE_LOW: Color = Color::Rgb(80, 120, 100);     // #507864
    pub const EMISSION_HOT: Color = Color::Rgb(255, 100, 50);  // #ff6432 - Orange
    pub const EMISSION_WARM: Color = Color::Rgb(255, 180, 100);// #ffb464
    pub const EMISSION_COOL: Color = Color::Rgb(150, 150, 180);// #9696b4

    // Network/TAO specific
    pub const TAO: Color = Color::Rgb(255, 215, 0);            // #ffd700 - Gold (TAO)
    pub const ALPHA: Color = Color::Rgb(200, 100, 255);        // #c864ff - Purple (Alpha tokens)
    pub const VALIDATOR: Color = Color::Rgb(100, 255, 200);    // #64ffc8 - Validator green
    pub const MINER: Color = Color::Rgb(255, 200, 100);        // #ffc864 - Miner amber
}

/// Pre-built styles for consistent UI
pub mod styles {
    use super::colors;
    use ratatui::style::{Modifier, Style};

    // Headers and titles
    pub fn title() -> Style {
        Style::default()
            .fg(colors::VOLT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn subtitle() -> Style {
        Style::default()
            .fg(colors::LIGHTNING)
            .add_modifier(Modifier::BOLD)
    }

    pub fn section_header() -> Style {
        Style::default()
            .fg(colors::TEXT_ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    // Text styles
    pub fn text_primary() -> Style {
        Style::default().fg(colors::TEXT_PRIMARY)
    }

    pub fn text_secondary() -> Style {
        Style::default().fg(colors::TEXT_SECONDARY)
    }

    pub fn text_dim() -> Style {
        Style::default().fg(colors::TEXT_TERTIARY)
    }

    // Status styles
    pub fn success() -> Style {
        Style::default().fg(colors::SUCCESS)
    }

    pub fn warning() -> Style {
        Style::default().fg(colors::WARNING)
    }

    pub fn error() -> Style {
        Style::default().fg(colors::ERROR)
    }

    pub fn info() -> Style {
        Style::default().fg(colors::INFO)
    }

    // Interactive elements
    pub fn selected() -> Style {
        Style::default()
            .bg(colors::BG_SELECTED)
            .add_modifier(Modifier::BOLD)
    }

    pub fn highlighted() -> Style {
        Style::default()
            .bg(colors::BG_HIGHLIGHT)
    }

    pub fn focused() -> Style {
        Style::default()
            .fg(colors::LIGHTNING)
            .add_modifier(Modifier::BOLD)
    }

    // Data styles
    pub fn tao_amount() -> Style {
        Style::default().fg(colors::TAO)
    }

    pub fn alpha_amount() -> Style {
        Style::default().fg(colors::ALPHA)
    }

    pub fn validator() -> Style {
        Style::default().fg(colors::VALIDATOR)
    }

    pub fn miner() -> Style {
        Style::default().fg(colors::MINER)
    }

    // Key hints
    pub fn key_hint() -> Style {
        Style::default()
            .fg(colors::VOLT)
            .add_modifier(Modifier::BOLD)
    }

    pub fn key_desc() -> Style {
        Style::default().fg(colors::TEXT_SECONDARY)
    }
}

/// Unicode symbols and characters for visual elements
pub mod symbols {
    // Box drawing - rounded corners
    pub const ROUNDED_TL: &str = "╭";
    pub const ROUNDED_TR: &str = "╮";
    pub const ROUNDED_BL: &str = "╰";
    pub const ROUNDED_BR: &str = "╯";
    pub const HORIZONTAL: &str = "─";
    pub const VERTICAL: &str = "│";
    pub const HORIZONTAL_HEAVY: &str = "━";
    pub const VERTICAL_HEAVY: &str = "┃";

    // Status indicators
    pub const CONNECTED: &str = "◉";
    pub const DISCONNECTED: &str = "○";
    pub const LOADING: &str = "◐";
    pub const SUCCESS: &str = "✓";
    pub const ERROR: &str = "✗";
    pub const WARNING: &str = "⚠";
    pub const INFO: &str = "ℹ";

    // Navigation
    pub const ARROW_RIGHT: &str = "▶";
    pub const ARROW_LEFT: &str = "◀";
    pub const ARROW_UP: &str = "▲";
    pub const ARROW_DOWN: &str = "▼";
    pub const CHEVRON_RIGHT: &str = "›";
    pub const CHEVRON_LEFT: &str = "‹";
    pub const SELECTOR: &str = "▸";

    // Data visualization
    pub const BULLET: &str = "•";
    pub const DIAMOND: &str = "◆";
    pub const DIAMOND_OUTLINE: &str = "◇";
    pub const STAR: &str = "★";
    pub const STAR_OUTLINE: &str = "☆";
    pub const LIGHTNING: &str = "⚡";
    pub const FIRE: &str = "🔥";

    // Sparkline characters (low to high)
    pub const SPARK: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    // Progress/gradient blocks
    pub const BLOCK_LIGHT: &str = "░";
    pub const BLOCK_MED: &str = "▒";
    pub const BLOCK_HEAVY: &str = "▓";
    pub const BLOCK_FULL: &str = "█";

    // Network/graph symbols
    pub const NODE: &str = "●";
    pub const NODE_OUTLINE: &str = "○";
    pub const LINK: &str = "─";
    pub const BRANCH: &str = "├";
    pub const BRANCH_END: &str = "└";
    pub const TREE_VERTICAL: &str = "│";

    // Dividers
    pub const DIVIDER_DOT: &str = "·····";
    pub const DIVIDER_DASH: &str = "─────";
    pub const DIVIDER_WAVE: &str = "∿∿∿∿∿";
    pub const DIVIDER_DOUBLE: &str = "═════";

    // Currency/TAO
    pub const TAO: &str = "τ";
    pub const ALPHA: &str = "α";
}

/// Sparkline generation utilities
pub mod sparkline {
    use super::symbols::SPARK;

    /// Generate a sparkline string from values
    pub fn from_values(values: &[f64]) -> String {
        if values.is_empty() {
            return String::new();
        }

        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let range = max - min;

        if range == 0.0 {
            return SPARK[4].to_string().repeat(values.len());
        }

        values
            .iter()
            .map(|&v| {
                let normalized = (v - min) / range;
                let idx = (normalized * 7.0).round() as usize;
                SPARK[idx.min(7)]
            })
            .collect()
    }

    /// Generate a sparkline for the last N values with color hints
    pub fn trend_indicator(current: f64, previous: f64) -> (&'static str, bool) {
        if current > previous * 1.05 {
            ("▲", true)  // Up, positive
        } else if current < previous * 0.95 {
            ("▼", false) // Down, negative
        } else {
            ("─", true)  // Stable
        }
    }
}

/// Gradient bar generation
pub mod gradient {
    use super::symbols::{BLOCK_FULL, BLOCK_HEAVY, BLOCK_MED, BLOCK_LIGHT};

    /// Generate a gradient progress bar
    pub fn progress_bar(percent: f64, width: usize) -> String {
        let filled = (percent * width as f64 / 100.0).round() as usize;
        let filled = filled.min(width);

        let mut bar = String::with_capacity(width);

        for i in 0..width {
            if i < filled.saturating_sub(1) {
                bar.push_str(BLOCK_FULL);
            } else if i == filled.saturating_sub(1) && filled > 0 {
                bar.push_str(BLOCK_HEAVY);
            } else if i == filled {
                bar.push_str(BLOCK_MED);
            } else if i == filled + 1 {
                bar.push_str(BLOCK_LIGHT);
            } else {
                bar.push(' ');
            }
        }

        bar
    }

    /// Generate a heat bar (cold to hot colors represented by density)
    pub fn heat_bar(value: f64, max: f64, width: usize) -> String {
        let percent = if max > 0.0 { (value / max) * 100.0 } else { 0.0 };
        progress_bar(percent, width)
    }
}

/// ASCII art banners
pub mod banners {
    /// Lightning Tensor small banner
    pub const BANNER_SMALL: &str = r#"
  ⚡ LIGHTNING TENSOR ⚡
"#;

    /// Decorative section header
    pub fn section_header(title: &str) -> String {
        let padding = 2;
        let total_width = title.len() + (padding * 2) + 4;
        let line = "─".repeat(total_width - 2);

        format!(
            "╭{}╮\n│  {}  │\n╰{}╯",
            line, title, line
        )
    }

    /// Inline section marker
    pub fn section_marker(title: &str) -> String {
        format!("──◆ {} ◆──", title)
    }
}

/// Helper to get style based on value thresholds
pub fn value_style(value: f64, low: f64, high: f64) -> Style {
    if value >= high {
        styles::success()
    } else if value >= low {
        styles::warning()
    } else if value > 0.0 {
        styles::text_secondary()
    } else {
        styles::text_dim()
    }
}

/// Helper to format TAO amounts with symbol
pub fn format_tao(amount: f64) -> String {
    if amount >= 1_000_000.0 {
        format!("{:.2}M {}", amount / 1_000_000.0, symbols::TAO)
    } else if amount >= 1_000.0 {
        format!("{:.2}K {}", amount / 1_000.0, symbols::TAO)
    } else if amount >= 1.0 {
        format!("{:.2} {}", amount, symbols::TAO)
    } else if amount > 0.0 {
        format!("{:.4} {}", amount, symbols::TAO)
    } else {
        format!("0 {}", symbols::TAO)
    }
}

/// Helper to format addresses with truncation
pub fn format_address(addr: &str, len: usize) -> String {
    if addr.len() <= len * 2 + 3 {
        addr.to_string()
    } else {
        format!("{}…{}", &addr[..len], &addr[addr.len()-len..])
    }
}
