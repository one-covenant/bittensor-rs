//! # Root Service
//!
//! Business logic for root network operations.

/// Service for root network operations
pub struct RootService;

impl RootService {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RootService {
    fn default() -> Self {
        Self::new()
    }
}
