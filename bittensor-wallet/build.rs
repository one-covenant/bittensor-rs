use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Auto-detect Python executable
    let python_executable = Command::new("which")
        .arg("python")
        .output()
        .expect("Failed to execute 'which python'")
        .stdout;
    let python_executable = String::from_utf8_lossy(&python_executable)
        .trim()
        .to_string();

    // Get Python version
    let python_version = Command::new(&python_executable)
        .args(&["--version"])
        .output()
        .expect("Failed to get Python version")
        .stdout;
    let python_version = String::from_utf8_lossy(&python_version).trim().to_string();

    // Extract major and minor version numbers
    let version_parts: Vec<&str> = python_version
        .split(' ')
        .last()
        .unwrap()
        .split('.')
        .collect();
    let major_version = version_parts[0];
    let minor_version = version_parts[1];

    // Construct Python lib directory path
    let python_path = PathBuf::from(&python_executable);
    let python_lib_dir = python_path.parent().unwrap().parent().unwrap().join("lib");

    // Print information for debugging
    println!("cargo:warning=Python executable: {}", python_executable);
    println!("cargo:warning=Python version: {}", python_version);
    println!("cargo:warning=Python lib dir: {}", python_lib_dir.display());

    // Set linker flags
    println!(
        "cargo:rustc-link-search=native={}",
        python_lib_dir.display()
    );
    println!(
        "cargo:rustc-link-lib=python{}.{}",
        major_version, minor_version
    );

    // Set rpath for tests
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "macos" {
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            python_lib_dir.display()
        );
    }
}
