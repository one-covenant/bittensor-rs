//! # TUI Components
//!
//! Reusable UI components for the TUI.
//! Features distinctive visual elements with cyberpunk aesthetic.

mod animation;
mod input;
mod popup;
mod spinner;
mod table;

pub use animation::{AnimationState, GradientProgress, Sparkline};
pub use input::InputField;
pub use popup::{Popup, PopupType};
pub use spinner::{LoadingIndicator, Spinner, SpinnerStyle};
pub use table::{DataTable, StyledCell};

