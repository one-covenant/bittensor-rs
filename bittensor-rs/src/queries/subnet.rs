//! # Subnet Queries
//!
//! Query subnet information from the Bittensor network.

use crate::api::api;
use crate::error::BittensorError;
use subxt::ext::codec;
use subxt::OnlineClient;
use subxt::PolkadotConfig;

/// Subnet information (basic)
#[derive(Debug, Clone)]
pub struct SubnetInfo {
    /// Subnet netuid
    pub netuid: u16,
    /// Subnet tempo (blocks per epoch)
    pub tempo: u16,
    /// Number of neurons
    pub n: u16,
    /// Maximum number of neurons
    pub max_n: u16,
    /// Immunity period
    pub immunity_period: u16,
    /// Registration allowed
    pub registration_allowed: bool,
}

/// Dynamic subnet info with DTAO data (single RPC call for all subnets)
#[derive(Debug, Clone)]
pub struct DynamicSubnetInfo {
    /// Subnet netuid
    pub netuid: u16,
    /// Subnet name (from identity or token symbol)
    pub name: String,
    /// Token symbol (e.g., "α", "τ")
    pub symbol: String,
    /// TAO emission per block (RAO)
    pub tao_in_emission: u64,
    /// Moving price (EMA) - used for emission weight calculation
    /// Emission % = moving_price / Σ all_moving_prices × 100
    pub moving_price: f64,
    /// Price in TAO (tao_in / alpha_in)
    pub price_tao: f64,
    /// Alpha in pool (RAO)
    pub alpha_in: u64,
    /// Alpha out pool (RAO)  
    pub alpha_out: u64,
    /// TAO in pool (RAO)
    pub tao_in: u64,
    /// Owner hotkey SS58
    pub owner_hotkey: String,
    /// Owner coldkey SS58
    pub owner_coldkey: String,
    /// Tempo (blocks per epoch)
    pub tempo: u16,
    /// Block number when subnet was registered
    pub registered_at: u64,
}

/// Subnet hyperparameters
#[derive(Debug, Clone)]
pub struct SubnetHyperparameters {
    /// Blocks per epoch
    pub tempo: u16,
    /// Maximum neurons
    pub max_n: u16,
    /// Minimum allowed weights
    pub min_allowed_weights: u16,
    /// Maximum allowed weights
    pub max_allowed_weights: u16,
    /// Weights version key
    pub weights_version_key: u64,
    /// Weights rate limit
    pub weights_rate_limit: u64,
    /// Registration allowed
    pub registration_allowed: bool,
    /// Adjustment interval
    pub adjustment_interval: u16,
    /// Target registration per interval
    pub target_regs_per_interval: u16,
    /// Immunity period
    pub immunity_period: u16,
}

/// Get information about a subnet
pub async fn get_subnet_info(
    client: &OnlineClient<PolkadotConfig>,
    netuid: u16,
) -> Result<SubnetInfo, BittensorError> {
    let storage = client
        .storage()
        .at_latest()
        .await
        .map_err(|e| BittensorError::RpcError {
            message: format!("Failed to get storage: {}", e),
        })?;

    let tempo = storage
        .fetch(&api::storage().subtensor_module().tempo(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "tempo".to_string(),
            message: e.to_string(),
        })?
        .ok_or(BittensorError::SubnetNotFound { netuid })?;

    let n = storage
        .fetch(&api::storage().subtensor_module().subnetwork_n(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "n".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let max_n = storage
        .fetch(&api::storage().subtensor_module().max_allowed_uids(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "max_n".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let immunity_period = storage
        .fetch(&api::storage().subtensor_module().immunity_period(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "immunity_period".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let registration_allowed = storage
        .fetch(
            &api::storage()
                .subtensor_module()
                .network_registration_allowed(netuid),
        )
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "registration_allowed".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(false);

    Ok(SubnetInfo {
        netuid,
        tempo,
        n,
        max_n,
        immunity_period,
        registration_allowed,
    })
}

/// Get hyperparameters for a subnet
pub async fn get_subnet_hyperparameters(
    client: &OnlineClient<PolkadotConfig>,
    netuid: u16,
) -> Result<SubnetHyperparameters, BittensorError> {
    let storage = client
        .storage()
        .at_latest()
        .await
        .map_err(|e| BittensorError::RpcError {
            message: format!("Failed to get storage: {}", e),
        })?;

    let tempo = storage
        .fetch(&api::storage().subtensor_module().tempo(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "tempo".to_string(),
            message: e.to_string(),
        })?
        .ok_or(BittensorError::SubnetNotFound { netuid })?;

    let max_n = storage
        .fetch(&api::storage().subtensor_module().max_allowed_uids(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "max_n".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let min_allowed_weights = storage
        .fetch(
            &api::storage()
                .subtensor_module()
                .min_allowed_weights(netuid),
        )
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "min_allowed_weights".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let max_allowed_weights = storage
        .fetch(&api::storage().subtensor_module().max_weights_limit(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "max_allowed_weights".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let weights_version_key = storage
        .fetch(
            &api::storage()
                .subtensor_module()
                .weights_version_key(netuid),
        )
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "weights_version_key".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let weights_rate_limit = storage
        .fetch(
            &api::storage()
                .subtensor_module()
                .weights_set_rate_limit(netuid),
        )
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "weights_rate_limit".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let registration_allowed = storage
        .fetch(
            &api::storage()
                .subtensor_module()
                .network_registration_allowed(netuid),
        )
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "registration_allowed".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(false);

    let adjustment_interval = storage
        .fetch(
            &api::storage()
                .subtensor_module()
                .adjustment_interval(netuid),
        )
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "adjustment_interval".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let target_regs_per_interval = storage
        .fetch(
            &api::storage()
                .subtensor_module()
                .target_registrations_per_interval(netuid),
        )
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "target_regs_per_interval".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    let immunity_period = storage
        .fetch(&api::storage().subtensor_module().immunity_period(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "immunity_period".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    Ok(SubnetHyperparameters {
        tempo,
        max_n,
        min_allowed_weights,
        max_allowed_weights,
        weights_version_key,
        weights_rate_limit,
        registration_allowed,
        adjustment_interval,
        target_regs_per_interval,
        immunity_period,
    })
}

/// Get the number of active subnets
pub async fn get_total_subnets(
    client: &OnlineClient<PolkadotConfig>,
) -> Result<u16, BittensorError> {
    let storage = client
        .storage()
        .at_latest()
        .await
        .map_err(|e| BittensorError::RpcError {
            message: format!("Failed to get storage: {}", e),
        })?;

    let count = storage
        .fetch(&api::storage().subtensor_module().total_networks())
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "total_networks".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(0);

    Ok(count)
}

/// Check if a subnet exists
pub async fn subnet_exists(
    client: &OnlineClient<PolkadotConfig>,
    netuid: u16,
) -> Result<bool, BittensorError> {
    let storage = client
        .storage()
        .at_latest()
        .await
        .map_err(|e| BittensorError::RpcError {
            message: format!("Failed to get storage: {}", e),
        })?;

    let exists = storage
        .fetch(&api::storage().subtensor_module().networks_added(netuid))
        .await
        .map_err(|e| BittensorError::StorageQueryError {
            key: "networks_added".to_string(),
            message: e.to_string(),
        })?
        .unwrap_or(false);

    Ok(exists)
}

/// Get all subnet dynamic info in a single RPC call
///
/// This is MUCH faster than calling get_subnet_info for each subnet.
/// Returns DTAO pricing, emission, identity, and pool info for all subnets.
pub async fn get_all_dynamic_info(
    client: &OnlineClient<PolkadotConfig>,
) -> Result<Vec<DynamicSubnetInfo>, BittensorError> {
    let runtime_api = client.runtime_api().at_latest().await.map_err(|e| {
        BittensorError::RpcError {
            message: format!("Failed to get runtime API: {}", e),
        }
    })?;

    let payload = api::apis().subnet_info_runtime_api().get_all_dynamic_info();
    let result = runtime_api.call(payload).await.map_err(|e| {
        BittensorError::RpcError {
            message: format!("Failed to call get_all_dynamic_info: {}", e),
        }
    })?;

    let subnets: Vec<DynamicSubnetInfo> = result
        .into_iter()
        .filter_map(|opt| opt)
        .map(|info| {
            // Decode subnet name from compact bytes
            let name = decode_compact_bytes(&info.subnet_name);
            let symbol = decode_compact_bytes(&info.token_symbol);

            // Extract identity name if available (identity uses plain Vec<u8>)
            let display_name = info
                .subnet_identity
                .as_ref()
                .and_then(|id| {
                    let n = String::from_utf8_lossy(&id.subnet_name).to_string();
                    if n.is_empty() { None } else { Some(n) }
                })
                .unwrap_or_else(|| name.clone());

            // Calculate price from pool ratio: tao_in / alpha_in
            // This is the actual exchange rate (how much TAO per 1 Alpha)
            let alpha_in_f = info.alpha_in as f64 / 1_000_000_000.0; // Convert RAO to TAO
            let tao_in_f = info.tao_in as f64 / 1_000_000_000.0;
            
            let price_tao = if info.netuid == 0 {
                1.0 // Root subnet always 1:1
            } else if alpha_in_f > 0.0 {
                tao_in_f / alpha_in_f
            } else {
                0.0
            };

            // Convert FixedI128<U32> to f64
            // The type parameter from metadata is U32 (32 fractional bits)
            // moving_price = bits / 2^32
            let moving_price = (info.moving_price.bits as f64) / ((1u64 << 32) as f64);

            DynamicSubnetInfo {
                netuid: info.netuid,
                name: if display_name.is_empty() { format!("SN{}", info.netuid) } else { display_name },
                symbol: if symbol.is_empty() { "α".to_string() } else { symbol },
                tao_in_emission: info.tao_in_emission,
                moving_price,
                price_tao,
                alpha_in: info.alpha_in,
                alpha_out: info.alpha_out,
                tao_in: info.tao_in,
                owner_hotkey: format!("{}", info.owner_hotkey),
                owner_coldkey: format!("{}", info.owner_coldkey),
                tempo: info.tempo,
                registered_at: info.network_registered_at,
            }
        })
        .collect();

    Ok(subnets)
}

/// Decode compact bytes (Vec<Compact<u8>>) to String
fn decode_compact_bytes(bytes: &[codec::Compact<u8>]) -> String {
    let raw: Vec<u8> = bytes.iter().map(|c| c.0).collect();
    String::from_utf8_lossy(&raw).to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_info_struct() {
        let info = SubnetInfo {
            netuid: 1,
            tempo: 360,
            n: 256,
            max_n: 4096,
            immunity_period: 100,
            registration_allowed: true,
        };

        assert_eq!(info.netuid, 1);
        assert_eq!(info.tempo, 360);
    }

    #[test]
    fn test_hyperparameters_struct() {
        let params = SubnetHyperparameters {
            tempo: 360,
            max_n: 4096,
            min_allowed_weights: 0,
            max_allowed_weights: 65535,
            weights_version_key: 0,
            weights_rate_limit: 100,
            registration_allowed: true,
            adjustment_interval: 112,
            target_regs_per_interval: 2,
            immunity_period: 100,
        };

        assert_eq!(params.tempo, 360);
        assert!(params.registration_allowed);
    }
}
