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

    // The `avx512` feature's dependency is selected by a
    // `cfg(target_feature = "avx512f", ...)` target table, and rustc only
    // reports those cfgs once the target features are stable, in 1.89. On an
    // earlier toolchain the cfg is never set, so `ed25519-simd` and
    // `ed_sigs::avx512` are omitted even when the documented
    // `-C target-feature=+avx512f,+avx512bw,+avx512dq,+avx512ifma` is passed:
    // the build succeeds and the API is simply absent. Fail loudly instead.
    if std::env::var_os("CARGO_FEATURE_AVX512").is_some()
        && rustc_version.major == 1
        && rustc_version.minor < 89
    {
        panic!(
            "the `avx512` feature requires Rust 1.89.0 or newer, found {rustc_version}. \
             Earlier toolchains never set `cfg(target_feature = \"avx512f\")`, which would \
             silently omit the `ed_sigs::avx512` API instead of failing to build."
        );
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

    // Single source of truth for the AVX-512 gate. `ed_sigs::avx512` needs both
    // the Cargo feature and every target feature `ed25519-simd` requires, which
    // is the same predicate that selects the dependency in `Cargo.toml`. Emit it
    // as one cfg so the modules that gate on it cannot drift out of sync — an
    // earlier revision had to fix a missing `avx512bw` in several copies at
    // once.
    if std::env::var_os("CARGO_FEATURE_AVX512").is_some()
        && target_arch == "x86_64"
        && has_target_features(AVX512_TARGET_FEATURES)
    {
        println!("cargo:rustc-cfg=ed25519_avx512");
    }
}

/// The target features `ed25519-simd` refuses to compile without.
const AVX512_TARGET_FEATURES: &[&str] = &["avx512f", "avx512bw", "avx512dq", "avx512ifma"];

/// Are all of `features` enabled for the target being compiled?
///
/// `CARGO_CFG_TARGET_FEATURE` reflects `-C target-feature` from `RUSTFLAGS`, so
/// this sees the same feature set as `cfg(target_feature = ...)` in the crate.
fn has_target_features(features: &[&str]) -> bool {
    let enabled = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    features
        .iter()
        .all(|feature| enabled.split(',').any(|enabled| enabled == *feature))
}

// Is the target arch potentially simd capable?
fn is_capable_simd(arch: &str) -> bool {
    arch == "x86_64"
}
