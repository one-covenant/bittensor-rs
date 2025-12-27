//! # Connection Management
//!
//! Connection pooling, health monitoring, and retry logic for Bittensor chain interactions.
//!
//! This module provides robust connection handling with:
//!
//! - **Connection Pool**: Manages multiple WebSocket connections with automatic failover
//! - **Health Checker**: Periodic health monitoring with configurable thresholds
//! - **Circuit Breaker**: Prevents cascade failures during extended outages
//! - **Retry Node**: Exponential backoff with jitter for transient errors
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    ConnectionPool                           │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │ Connection 1│  │ Connection 2│  │ Connection 3│  ...    │
//! │  │  (healthy)  │  │  (healthy)  │  │ (unhealthy) │         │
//! │  └─────────────┘  └─────────────┘  └─────────────┘         │
//! │         │                │                                  │
//! │         └────────────────┼──────────────────────────────────│
//! │                          ▼                                  │
//! │                   HealthChecker                             │
//! │              (periodic monitoring)                          │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use bittensor_rs::connect::{ConnectionPoolBuilder, RetryConfig, HealthChecker};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let endpoints = vec![
//!     "wss://entrypoint-finney.opentensor.ai:443".to_string(),
//! ];
//!
//! let pool = Arc::new(
//!     ConnectionPoolBuilder::new(endpoints)
//!         .max_connections(3)
//!         .retry_config(RetryConfig::network())
//!         .build()
//! );
//!
//! pool.initialize().await?;
//!
//! // Get a healthy client
//! let client = pool.get_healthy_client().await?;
//! # Ok(())
//! # }
//! ```

pub mod health;
pub mod monitor;
pub mod pool;
pub mod state;

// Re-export core types from submodules
pub use crate::error::RetryConfig;
pub use crate::retry::{CircuitBreaker, ExponentialBackoff, RetryNode};
pub use health::{ConnectionPoolTrait, HealthCheckMetrics, HealthChecker};
pub use monitor::{BlockchainMonitor, TransferInfo};
pub use pool::{ConnectionPool, ConnectionPoolBuilder};
pub use state::{ConnectionManager, ConnectionMetricsSnapshot, ConnectionState};

/// Common imports for connection-related code
pub mod prelude {
    pub use super::{
        BlockchainMonitor, CircuitBreaker, ConnectionManager, ConnectionMetricsSnapshot,
        ConnectionPool, ConnectionPoolBuilder, ConnectionPoolTrait, ConnectionState,
        ExponentialBackoff, HealthCheckMetrics, HealthChecker, RetryConfig, RetryNode,
    };
}
