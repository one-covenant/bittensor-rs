//! # Animation State
//!
//! Animation state management for TUI elements.
//! Provides multiple animation patterns for a dynamic interface.

use std::time::{Duration, Instant};

/// Duration of each animation frame
const ANIMATION_FRAME_DURATION: Duration = Duration::from_millis(80);

/// Braille spinner patterns
const SPINNER_BRAILLE: [char; 8] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];

/// Dot spinner patterns
const SPINNER_DOTS: [char; 8] = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];

/// Moon phase spinner
#[allow(dead_code)]
const SPINNER_MOON: [char; 8] = ['🌑', '🌒', '🌓', '🌔', '🌕', '🌖', '🌗', '🌘'];

/// Node pulsing pattern
const NODE_PULSE: [char; 8] = ['○', '◔', '◑', '◕', '●', '◕', '◑', '◔'];

/// Lightning pulse pattern
const LIGHTNING_PULSE: [&str; 6] = ["⚡", "⚡", "✦", "✧", "·", "·"];

/// Wave pattern for backgrounds
const WAVE_CHARS: [char; 8] = ['░', '▒', '▓', '█', '▓', '▒', '░', ' '];

/// Progress bar fill patterns
#[allow(dead_code)]
const PROGRESS_FILL: [&str; 4] = ["░", "▒", "▓", "█"];

/// Animation state for UI elements
pub struct AnimationState {
    pub frame: usize,
    pub last_update: Instant,
    pub slow_frame: usize,
    pub last_slow_update: Instant,
}

impl Default for AnimationState {
    fn default() -> Self {
        Self::new()
    }
}

impl AnimationState {
    pub fn new() -> Self {
        Self {
            frame: 0,
            last_update: Instant::now(),
            slow_frame: 0,
            last_slow_update: Instant::now(),
        }
    }

    pub fn update(&mut self) {
        let now = Instant::now();

        // Fast animation (80ms per frame)
        if now.duration_since(self.last_update) >= ANIMATION_FRAME_DURATION {
            self.frame = (self.frame + 1) % 8;
            self.last_update = now;
        }

        // Slow animation (400ms per frame) for subtle effects
        if now.duration_since(self.last_slow_update) >= Duration::from_millis(400) {
            self.slow_frame = (self.slow_frame + 1) % 6;
            self.last_slow_update = now;
        }
    }

    /// Get braille spinner character for current frame
    pub fn spinner_char(&self) -> char {
        SPINNER_BRAILLE[self.frame]
    }

    /// Get dot spinner character
    pub fn spinner_dots(&self) -> char {
        SPINNER_DOTS[self.frame]
    }

    /// Get rotating node character
    pub fn node_char(&self) -> char {
        NODE_PULSE[self.frame]
    }

    /// Get lightning pulse string
    pub fn lightning_pulse(&self) -> &'static str {
        LIGHTNING_PULSE[self.slow_frame]
    }

    /// Get wave character for background effects
    pub fn wave_char(&self, offset: usize) -> char {
        WAVE_CHARS[(self.frame + offset) % 8]
    }

    /// Generate an animated loading bar
    pub fn loading_bar(&self, width: usize) -> String {
        let mut bar = String::with_capacity(width);
        let pos = self.frame % width;

        for i in 0..width {
            let dist = (i as i32 - pos as i32).unsigned_abs() as usize;
            if dist == 0 {
                bar.push('█');
            } else if dist == 1 {
                bar.push('▓');
            } else if dist == 2 {
                bar.push('▒');
            } else if dist == 3 {
                bar.push('░');
            } else {
                bar.push(' ');
            }
        }

        bar
    }

    /// Generate bouncing loading indicator
    pub fn bouncing_loader(&self, width: usize) -> String {
        let mut bar = String::with_capacity(width);
        // Bounce effect using sine-like pattern
        let bounce_frames = width * 2 - 2;
        let pos = self.frame % bounce_frames.max(1);
        let actual_pos = if pos < width {
            pos
        } else {
            bounce_frames - pos
        };

        for i in 0..width {
            if i == actual_pos {
                bar.push('⚡');
            } else {
                bar.push('·');
            }
        }

        bar
    }

    /// Get animated connection status indicator
    pub fn connection_indicator(&self, connected: bool) -> (&'static str, &'static str) {
        if connected {
            match self.slow_frame % 3 {
                0 => ("◉", "Connected"),
                1 => ("●", "Connected"),
                _ => ("◉", "Connected"),
            }
        } else {
            match self.slow_frame % 3 {
                0 => ("○", "Disconnected"),
                1 => ("◌", "Disconnected"),
                _ => ("○", "Disconnected"),
            }
        }
    }

    /// Generate animated network mesh for logo
    pub fn network_logo(&self) -> Vec<String> {
        let node = self.node_char();
        let pulse = if self.frame % 4 < 2 { '─' } else { '━' };

        vec![
            format!("     {}{pulse}{}{pulse}{}     ", node, node, node),
            "    ╱ ╲ ╱ ╲ ╱ ╲    ".to_string(),
            format!(
                "   {}{pulse}{}{pulse}{}{pulse}{}   ",
                node, node, node, node
            ),
            "  ╱ ╲ ╱ ╲ ╱ ╲ ╱ ╲  ".to_string(),
            format!(
                " {}{pulse}{}{pulse}{}{pulse}{}{pulse}{} ",
                node, node, node, node, node
            ),
            "  ╲ ╱ ╲ ╱ ╲ ╱ ╲ ╱  ".to_string(),
            format!(
                "   {}{pulse}{}{pulse}{}{pulse}{}   ",
                node, node, node, node
            ),
            "    ╲ ╱ ╲ ╱ ╲ ╱    ".to_string(),
            format!("     {}{pulse}{}{pulse}{}     ", node, node, node),
        ]
    }
}

/// Sparkline widget helper
pub struct Sparkline {
    values: Vec<f64>,
    min: f64,
    max: f64,
}

impl Sparkline {
    const CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    pub fn new(values: Vec<f64>) -> Self {
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        Self { values, min, max }
    }

    pub fn with_range(values: Vec<f64>, min: f64, max: f64) -> Self {
        Self { values, min, max }
    }

    pub fn render(&self) -> String {
        if self.values.is_empty() {
            return String::new();
        }

        let range = self.max - self.min;
        if range == 0.0 {
            return Self::CHARS[4].to_string().repeat(self.values.len());
        }

        self.values
            .iter()
            .map(|&v| {
                let normalized = ((v - self.min) / range).clamp(0.0, 1.0);
                let idx = (normalized * 7.0).round() as usize;
                Self::CHARS[idx.min(7)]
            })
            .collect()
    }

    /// Render with color zones (returns tuples of (char, zone))
    /// zone: 0 = low, 1 = mid, 2 = high
    pub fn render_with_zones(&self, low_threshold: f64, high_threshold: f64) -> Vec<(char, u8)> {
        if self.values.is_empty() {
            return vec![];
        }

        let range = self.max - self.min;
        if range == 0.0 {
            return self.values.iter().map(|_| (Self::CHARS[4], 1)).collect();
        }

        self.values
            .iter()
            .map(|&v| {
                let normalized = ((v - self.min) / range).clamp(0.0, 1.0);
                let idx = (normalized * 7.0).round() as usize;
                let zone = if v >= high_threshold {
                    2
                } else if v >= low_threshold {
                    1
                } else {
                    0
                };
                (Self::CHARS[idx.min(7)], zone)
            })
            .collect()
    }
}

/// Progress bar with gradient effect
pub struct GradientProgress {
    percent: f64,
    width: usize,
}

impl GradientProgress {
    pub fn new(percent: f64, width: usize) -> Self {
        Self {
            percent: percent.clamp(0.0, 100.0),
            width,
        }
    }

    pub fn render(&self) -> String {
        let filled = (self.percent * self.width as f64 / 100.0).round() as usize;
        let filled = filled.min(self.width);

        let mut bar = String::with_capacity(self.width);

        for i in 0..self.width {
            if i < filled.saturating_sub(2) {
                bar.push('█');
            } else if i == filled.saturating_sub(2) && filled > 1 {
                bar.push('▓');
            } else if i == filled.saturating_sub(1) && filled > 0 {
                bar.push('▒');
            } else if i == filled {
                bar.push('░');
            } else {
                bar.push('·');
            }
        }

        bar
    }

    /// Render with brackets
    pub fn render_bracketed(&self) -> String {
        format!("[{}]", self.render())
    }
}
