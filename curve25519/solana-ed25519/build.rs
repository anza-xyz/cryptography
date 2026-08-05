//! This codebase is pinned to the 64-bit backend. The arithmetic backend
//! defaults to x86_64 SIMD and can be overridden to `serial` with
//! `RUSTFLAGS='--cfg curve25519_backend="serial"'`.

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

    // Backend override / default.
    //
    // `simd` compiles in the AVX2 vector backend and picks between it and the
    // serial backend per-host at runtime, see `backend::get_selected_backend`.
    // `serial` compiles the vector backend out entirely, which is what
    // instrumented builds want: coverage counters on the AVX2 field arithmetic
    // are pathologically slow at any opt-level.
    let curve25519_backend = match std::env::var("CARGO_CFG_CURVE25519_BACKEND").as_deref() {
        Ok("serial") => "serial",
        // If the override is not possible this must result in a compile error.
        // See: dalek issues/532
        Ok("simd") if !is_capable_simd(&target_arch) => {
            panic!("Could not override curve25519_backend to simd")
        }
        Ok("simd") => "simd",
        Ok(other) => {
            panic!("Unknown curve25519_backend {other:?}, expected \"simd\" or \"serial\"")
        }
        // Default to simd wherever it is available.
        Err(_) => match is_capable_simd(&target_arch) {
            true => "simd",
            false => "serial",
        },
    };

    println!("cargo:rustc-cfg=curve25519_bits=\"64\"");
    println!("cargo:rustc-cfg=curve25519_backend=\"{curve25519_backend}\"");
}

// Is the target arch potentially simd capable?
fn is_capable_simd(arch: &str) -> bool {
    arch == "x86_64"
}
