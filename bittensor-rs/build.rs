//! Build script for bittensor crate

fn main() {
    // Rerun if the api.rs changes (which contains the subxt macro)
    println!("cargo:rerun-if-changed=src/api.rs");
}
