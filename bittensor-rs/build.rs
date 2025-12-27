//! Build script for bittensor crate
//!
//! Fetches the latest metadata from the Bittensor chain and regenerates
//! the Rust bindings if the metadata has changed.
//!
//! No external CLI tools required - uses subxt libraries directly.

use std::env;
use std::fs;
use std::path::Path;

use parity_scale_codec::Decode;
use sha2::{Digest, Sha256};
use subxt_codegen::CodegenBuilder;
use subxt_metadata::Metadata;
use subxt_utils_fetchmetadata::{from_url_blocking, MetadataVersion, Url};

const FINNEY_ENDPOINT: &str = "wss://entrypoint-finney.opentensor.ai:443";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR not set");
    let metadata_path = Path::new(&out_dir).join("metadata.scale");
    let code_path = Path::new(&out_dir).join("metadata.rs");
    let hash_path = Path::new(&out_dir).join("metadata.hash");

    // Check environment variable to skip network fetch (for offline builds)
    if env::var("BITTENSOR_OFFLINE").is_ok() {
        println!("cargo:warning=BITTENSOR_OFFLINE set, skipping metadata fetch");
        if !code_path.exists() {
            panic!(
                "Offline mode but no cached code exists at {:?}",
                code_path
            );
        }
        return;
    }

    // Determine endpoint from environment or default to finney
    let endpoint = env::var("BITTENSOR_ENDPOINT").unwrap_or_else(|_| FINNEY_ENDPOINT.to_string());

    println!("cargo:warning=Fetching metadata from {}", endpoint);

    // Parse URL
    let url = Url::parse(&endpoint).expect("Invalid endpoint URL");

    // Fetch metadata using subxt-utils-fetchmetadata (includes runtime APIs)
    let metadata_bytes = match from_url_blocking(url, MetadataVersion::Latest) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("cargo:warning=Failed to fetch metadata: {}", e);
            // If we have cached code, use it
            if code_path.exists() {
                println!("cargo:warning=Using cached generated code");
                return;
            }
            panic!("No cached code and failed to fetch metadata: {}", e);
        }
    };

    // Hash the metadata to detect changes
    let mut hasher = Sha256::new();
    hasher.update(&metadata_bytes);
    let new_hash = format!("{:x}", hasher.finalize());

    // Check if metadata has changed
    let should_regenerate = if let Ok(old_hash) = fs::read_to_string(&hash_path) {
        if old_hash.trim() == new_hash {
            println!("cargo:warning=Metadata unchanged, using cached code");
            false
        } else {
            println!("cargo:warning=Metadata changed, regenerating code");
            true
        }
    } else {
        println!("cargo:warning=No cached hash, generating code");
        true
    };

    if should_regenerate {
        // Save metadata for debugging/reference
        fs::write(&metadata_path, &metadata_bytes).expect("Failed to write metadata.scale");

        // Decode metadata
        let metadata =
            Metadata::decode(&mut &metadata_bytes[..]).expect("Failed to decode metadata");

        // Generate Rust code
        let code = CodegenBuilder::new()
            .generate(metadata)
            .expect("Failed to generate code from metadata");

        // Add suppressions but don't wrap - the generated code already has structure
        let wrapped_code = format!(
            "#[allow(dead_code, unused_imports, non_camel_case_types)]\n\
             #[allow(clippy::all)]\n\
             {}",
            code
        );

        // Write the generated code
        fs::write(&code_path, wrapped_code).expect("Failed to write metadata.rs");

        // Save the hash
        fs::write(&hash_path, &new_hash).expect("Failed to write metadata.hash");

        println!(
            "cargo:warning=Generated code from {} bytes of metadata",
            metadata_bytes.len()
        );
    }
}
