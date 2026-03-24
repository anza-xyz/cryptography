//! This codebase is pinned to x86_64 SIMD + 64-bit backend.

#![deny(clippy::unwrap_used, dead_code)]

fn main() {
    let target_arch = match std::env::var("CARGO_CFG_TARGET_ARCH") {
        Ok(arch) => arch,
        _ => "".to_string(),
    };

    let rustc_version = rustc_version::version().expect("failed to detect rustc version");
    if rustc_version.major == 1 && rustc_version.minor <= 64 {
        // Old versions of Rust complain when you have an `unsafe fn` and you use `unsafe {}` inside,
        // so for those we want to apply the `#[allow(unused_unsafe)]` attribute to get rid of that warning.
        println!("cargo:rustc-cfg=allow_unused_unsafe");
    }

    let _ = target_arch;

    println!("cargo:rustc-cfg=curve25519_bits=\"64\"");
    println!("cargo:rustc-cfg=curve25519_backend=\"simd\"");
}
