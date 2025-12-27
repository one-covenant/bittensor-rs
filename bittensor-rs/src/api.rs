//! API module that includes the generated metadata
//! This allows us to use our own metadata instead of crabtensor's built-in metadata

#[subxt::subxt(runtime_metadata_path = "metadata/finney.scale")]
pub mod api {}
