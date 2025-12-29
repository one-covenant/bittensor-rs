//! Build script for bittensor crate
//!
//! Fetches the latest metadata from the Bittensor chain and regenerates
//! the Rust bindings if the metadata has changed.
//!
//! For docs.rs and offline builds, uses bundled metadata from metadata/finney.scale

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
    println!("cargo:rerun-if-changed=metadata/finney.scale");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR not set");
    let metadata_path = Path::new(&out_dir).join("metadata.scale");
    let code_path = Path::new(&out_dir).join("metadata.rs");
    let hash_path = Path::new(&out_dir).join("metadata.hash");

    // Path to bundled metadata (relative to crate root)
    let bundled_metadata_path = Path::new("metadata/finney.scale");

    // Check if we're in docs.rs or offline mode - use bundled metadata
    let use_bundled = env::var("DOCS_RS").is_ok() || env::var("BITTENSOR_OFFLINE").is_ok();

    if use_bundled {
        println!("cargo:warning=Using bundled metadata (docs.rs or offline mode)");
        generate_from_bundled(bundled_metadata_path, &code_path, &hash_path);
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

            // If we have cached code in OUT_DIR, use it
            if code_path.exists() {
                println!("cargo:warning=Using cached generated code");
                return;
            }

            // Fall back to bundled metadata
            if bundled_metadata_path.exists() {
                println!("cargo:warning=Falling back to bundled metadata");
                generate_from_bundled(bundled_metadata_path, &code_path, &hash_path);
                return;
            }

            panic!("No cached code and failed to fetch metadata: {}", e);
        }
    };

    generate_from_bytes(&metadata_bytes, &metadata_path, &code_path, &hash_path);
}

fn generate_from_bundled(bundled_path: &Path, code_path: &Path, hash_path: &Path) {
    let metadata_bytes = fs::read(bundled_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read bundled metadata from {:?}: {}",
            bundled_path, e
        )
    });

    // Generate code from bundled metadata
    generate_code(&metadata_bytes, code_path, hash_path);
}

fn generate_from_bytes(
    metadata_bytes: &[u8],
    metadata_path: &Path,
    code_path: &Path,
    hash_path: &Path,
) {
    // Hash the metadata to detect changes
    let mut hasher = Sha256::new();
    hasher.update(metadata_bytes);
    let new_hash = format!("{:x}", hasher.finalize());

    // Check if metadata has changed
    let should_regenerate = if let Ok(old_hash) = fs::read_to_string(hash_path) {
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
        fs::write(metadata_path, metadata_bytes).expect("Failed to write metadata.scale");
        generate_code(metadata_bytes, code_path, hash_path);
    }
}

fn generate_code(metadata_bytes: &[u8], code_path: &Path, hash_path: &Path) {
    // Hash for cache
    let mut hasher = Sha256::new();
    hasher.update(metadata_bytes);
    let new_hash = format!("{:x}", hasher.finalize());

    // Decode metadata
    let metadata = Metadata::decode(&mut &metadata_bytes[..]).expect("Failed to decode metadata");

    // Generate Rust code
    let code = CodegenBuilder::new()
        .generate(metadata)
        .expect("Failed to generate code from metadata");

    // Add suppressions
    let wrapped_code = format!(
        "#[allow(dead_code, unused_imports, non_camel_case_types)]\n\
         #[allow(clippy::all)]\n\
         {}",
        code
    );

    // Write the generated code
    fs::write(code_path, wrapped_code).expect("Failed to write metadata.rs");

    // Save the hash
    fs::write(hash_path, &new_hash).expect("Failed to write metadata.hash");

    println!(
        "cargo:warning=Generated code from {} bytes of metadata",
        metadata_bytes.len()
    );
}
