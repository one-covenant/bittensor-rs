//! # Animation State
//!
//! Animation state management for TUI elements.

use std::time::{Duration, Instant};

/// Duration of each animation frame
const ANIMATION_FRAME_DURATION: Duration = Duration::from_millis(100);

/// Animation state for UI elements
pub struct AnimationState {
    pub frame: usize,
    pub last_update: Instant,
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
        }
    }

    pub fn update(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_update) >= ANIMATION_FRAME_DURATION {
            self.frame = (self.frame + 1) % 8;
            self.last_update = now;
        }
    }
    
    /// Get spinner character for current frame
    pub fn spinner_char(&self) -> char {
        const SPINNER_CHARS: [char; 8] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];
        SPINNER_CHARS[self.frame]
    }
    
    /// Get rotating node character
    pub fn node_char(&self) -> char {
        const NODE_CHARS: [char; 8] = ['○', '◔', '◑', '◕', '●', '◕', '◑', '◔'];
        NODE_CHARS[self.frame]
    }
}

