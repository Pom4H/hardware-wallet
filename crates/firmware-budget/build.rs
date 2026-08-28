use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=memory.x");
    if env::var_os("CARGO_FEATURE_EMBEDDED_PROBE").is_none() {
        return;
    }

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    if env::var_os("CARGO_FEATURE_FIRMVERSE_PROBE").is_some() {
        fs::write(output.join("memory.x"), b"MEMORY\n{\n  FLASH : ORIGIN = 0x10000000, LENGTH = 1024K\n  RAM   : ORIGIN = 0x38000000, LENGTH = 256K\n}\n\n_stack_start = ORIGIN(RAM) + LENGTH(RAM);\n").expect("write Firmverse secure memory layout");
    } else {
        fs::write(output.join("memory.x"), include_bytes!("memory.x"))
            .expect("write generic probe memory layout");
    }
    println!("cargo:rustc-link-search={}", output.display());
    // cortex-m-rt supplies link.x; memory.x above supplies only the generic regions.
    println!("cargo:rustc-link-arg-bin=hardware-wallet-firmware-budget=-Tlink.x");
}
