//! # Display Traits
//!
//! Formatting utilities for CLI and TUI output.

use bittensor_rs::Balance;

/// Format a balance for display
pub fn format_tao(balance: &Balance) -> String {
    format!("{:.4} τ", balance.as_tao())
}

/// Format a balance in RAO for display
pub fn format_rao(balance: &Balance) -> String {
    format!("{} ρ", balance.as_rao())
}

/// Truncate an address for display
pub fn truncate_address(address: &str, prefix_len: usize, suffix_len: usize) -> String {
    if address.len() <= prefix_len + suffix_len + 3 {
        return address.to_string();
    }

    format!(
        "{}...{}",
        &address[..prefix_len],
        &address[address.len() - suffix_len..]
    )
}

/// Format a u16 weight as percentage
pub fn format_weight_pct(weight: u16) -> String {
    format!("{:.2}%", (weight as f64 / 65535.0) * 100.0)
}

/// Format a u16 as normalized decimal (0.0 - 1.0)
pub fn format_normalized(value: u16) -> String {
    format!("{:.4}", value as f64 / 65535.0)
}

/// Format block number with commas
pub fn format_blocks(blocks: u64) -> String {
    let s = blocks.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().rev().collect();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_address() {
        let addr = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        assert_eq!(truncate_address(addr, 6, 4), "5Grwva...tQY");
    }

    #[test]
    fn test_format_blocks() {
        assert_eq!(format_blocks(1000), "1,000");
        assert_eq!(format_blocks(1000000), "1,000,000");
        assert_eq!(format_blocks(123), "123");
    }

    #[test]
    fn test_format_normalized() {
        assert_eq!(format_normalized(65535), "1.0000");
        assert_eq!(format_normalized(32767), "0.5000");
    }
}
