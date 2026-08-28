use std::{env, fs, path::PathBuf};

fn main() {
    if env::var_os("CARGO_FEATURE_FIRMWARE").is_none() {
        return;
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(out.join("memory.x"), include_bytes!("memory.x"))
        .expect("write Firmverse browser memory layout");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
}
