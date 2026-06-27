//! Compile the `env run --harden` LD_PRELOAD shim (`shim/harden.c`) into a
//! shared object that the binary embeds with `include_bytes!`. On non-Linux
//! targets the shim is unused, so we emit an empty placeholder file just so the
//! `include_bytes!` in `run.rs` still resolves.

use std::path::Path;

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let so_path = Path::new(&out_dir).join("harden.so");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        std::fs::write(&so_path, b"").expect("failed to write placeholder harden.so");
        return;
    }

    println!("cargo:rerun-if-changed=shim/harden.c");

    let compiler = cc::Build::new().get_compiler();
    let mut cmd = compiler.to_command();
    // Hardening flags for this small but security-critical C component.
    // _FORTIFY_SOURCE needs optimization (-O2) to take effect.
    cmd.args([
        "-shared",
        "-fPIC",
        "-O2",
        "-fstack-protector-strong",
        "-fno-strict-aliasing",
        "-D_FORTIFY_SOURCE=2",
        "-o",
    ])
    .arg(&so_path)
    .arg("shim/harden.c");

    let status = cmd
        .status()
        .expect("failed to invoke the C compiler to build shim/harden.c");
    if !status.success() {
        panic!("compiling shim/harden.c into harden.so failed");
    }
}
