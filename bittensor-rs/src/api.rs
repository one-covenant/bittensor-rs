//! API module that includes the generated metadata
//!
//! The metadata is automatically fetched from the chain at build time
//! by the build.rs script using subxt-cli and subxt-codegen.
//!
//! Set BITTENSOR_OFFLINE=1 to skip metadata fetch and use cached version.
//! Set BITTENSOR_ENDPOINT to use a different chain endpoint.

include!(concat!(env!("OUT_DIR"), "/metadata.rs"));
