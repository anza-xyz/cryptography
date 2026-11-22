//! Run-time selection of the native x86_64 kernels.
//!
//! Each check is a cached atomic load (two for IFMA), and a constant when the
//! build already enables the features, so callers can test it on every
//! operation.
//!
//! Benchmarks can measure the paths other CPUs take by disabling a kernel with
//! `--cfg bn254_disable="ifma"` or `--cfg bn254_disable="adx"`.

use core::sync::atomic::{AtomicU8, Ordering::Relaxed};

// Only Linux builds include the ADX kernel this detects.
#[cfg(target_os = "linux")]
cpufeatures::new!(adx_bmi2, "adx", "bmi2");
// `#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]` also enables the
// features those three imply, so a kernel may only run when all of them are
// present:
// <https://doc.rust-lang.org/reference/attributes/codegen.html#r-attributes.codegen.target_feature.x86>.
// SSE and SSE2 are part of x86_64. `cpufeatures` cannot detect F16C, so
// `has_f16c` does.
cpufeatures::new!(
    avx512_ifma,
    "avx512f",
    "avx512dq",
    "avx512ifma",
    "avx2",
    "fma",
    "avx",
    "sse4.2",
    "sse4.1",
    "ssse3",
    "sse3"
);

/// Whether CPUID reports F16C, cached like the `cpufeatures` checks.
///
/// Call this only after `avx512_ifma::get()` returns true. That call checks
/// the OS support for the AVX state F16C uses. It also means CPUID never runs
/// on targets without it, such as SGX: `get()` is true there only if the build
/// enables AVX-512 F, and then F16C is enabled too and this function returns a
/// constant.
#[inline(always)]
fn has_f16c() -> bool {
    const UNKNOWN: u8 = u8::MAX;
    static F16C: AtomicU8 = AtomicU8::new(UNKNOWN);

    #[cold]
    fn detect() -> bool {
        // `__cpuid` is a safe function from Rust 1.94.
        #[allow(unused_unsafe)]
        // SAFETY: every x86_64 CPU has CPUID and its leaf 1, and the caller
        // rules out SGX.
        let leaf = unsafe { core::arch::x86_64::__cpuid(1) };
        let detected = leaf.ecx & (1 << 29) != 0;
        F16C.store(detected as u8, Relaxed);
        detected
    }

    if cfg!(target_feature = "f16c") {
        return true;
    }
    match F16C.load(Relaxed) {
        UNKNOWN => detect(),
        cached => cached != 0,
    }
}

/// Whether the CPU supports the ADX/BMI2 Montgomery multiplication kernel.
#[cfg(target_os = "linux")]
#[inline(always)]
pub(crate) fn has_adx() -> bool {
    !cfg!(bn254_disable = "adx") && adx_bmi2::get()
}

/// Whether to use the AVX-512 IFMA kernels: true when `ifma_supported` is,
/// unless the build disables them with `bn254_disable`.
#[inline(always)]
pub(crate) fn has_ifma() -> bool {
    !cfg!(bn254_disable = "ifma") && ifma_supported()
}

/// Whether the CPU and OS support every feature the AVX-512 IFMA kernels are
/// compiled with.
#[inline(always)]
pub fn ifma_supported() -> bool {
    avx512_ifma::get() && has_f16c()
}
