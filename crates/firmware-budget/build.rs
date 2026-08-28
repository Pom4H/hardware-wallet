use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=memory.x");
    if env::var_os("CARGO_FEATURE_EMBEDDED_PROBE").is_none() {
        return;
    }

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(output.join("memory.x"), include_bytes!("memory.x"))
        .expect("write generic probe memory layout");
    println!("cargo:rustc-link-search={}", output.display());
}
