//! Tool to generate metadata files for different Bittensor networks
//!
//! Usage: cargo run --bin generate-metadata --features generate-metadata -- [network]
//!
//! Networks: finney, test, local

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::process::{Command, Stdio};

use parity_scale_codec::Decode;
use subxt_codegen::CodegenBuilder;
use subxt_metadata::Metadata;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let network = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    // Create metadata directory if it doesn't exist
    fs::create_dir_all("metadata").expect("Failed to create metadata directory");

    match network {
        "all" => {
            generate_metadata("finney", "wss://entrypoint-finney.opentensor.ai:443").await;
            generate_metadata("test", "wss://test.finney.opentensor.ai:443").await;
            println!("Skipping local network - requires running local node");
        }
        "finney" => {
            generate_metadata("finney", "wss://entrypoint-finney.opentensor.ai:443").await;
        }
        "test" => {
            generate_metadata("test", "wss://test.finney.opentensor.ai:443").await;
        }
        "local" => {
            let endpoint =
                env::var("LOCAL_ENDPOINT").unwrap_or_else(|_| "ws://localhost:9944".to_string());
            generate_metadata("local", &endpoint).await;
        }
        _ => {
            eprintln!("Unknown network: {network}");
            eprintln!("Usage: cargo run --bin generate-metadata --features generate-metadata -- [network]");
            eprintln!("Networks: finney, test, local, all");
            std::process::exit(1);
        }
    }
}

async fn generate_metadata(network: &str, endpoint: &str) {
    println!("Generating metadata for {network} network from {endpoint}");

    // Fetch metadata using subxt CLI approach - download the scale bytes
    let metadata_bytes = match fetch_metadata_bytes(endpoint).await {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to fetch metadata for {network}: {e}");
            return;
        }
    };

    // Decode the metadata
    let metadata = match Metadata::decode(&mut &metadata_bytes[..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to decode metadata for {network}: {e}");
            return;
        }
    };

    // Generate code
    let code = CodegenBuilder::new()
        .generate(metadata)
        .expect("Failed to generate code from metadata");

    let output_path = format!("metadata/{network}.rs");

    // Try to format the code
    let formatted_code = match Command::new("rustfmt")
        .arg("--edition=2021")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(mut process) => {
            if let Some(stdin) = process.stdin.as_mut() {
                write!(stdin, "{code}").expect("Failed to write to rustfmt");
            }
            match process.wait_with_output() {
                Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
                Err(_) => code.to_string(),
            }
        }
        Err(_) => code.to_string(),
    };

    // Write the metadata file
    let mut file = File::create(&output_path).expect("Failed to create metadata file");
    write!(file, "{formatted_code}").expect("Failed to write metadata");

    println!("Generated metadata for {network} network at {output_path}");
}

async fn fetch_metadata_bytes(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use subxt::backend::rpc::RpcClient;
    use subxt::backend::legacy::LegacyRpcMethods;
    use subxt::PolkadotConfig;
    
    // Connect via RPC and fetch raw metadata bytes
    let rpc_client = RpcClient::from_insecure_url(url).await?;
    let rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client);
    let metadata_response = rpc.state_get_metadata(None).await?;
    // Convert the response to bytes
    Ok(metadata_response.into_raw())
}

