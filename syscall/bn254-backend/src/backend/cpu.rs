//! Run-time selection of the native x86_64 kernels.
//!
//! Each check is a cached atomic load, and a constant when the build already
//! enables the features, so callers can test it on every operation.
//!
//! Benchmarks can measure the paths other CPUs take by disabling a kernel with
//! `--cfg bn254_disable="ifma"` or `--cfg bn254_disable="adx"`.

// Only Linux builds include the ADX kernel this detects.
#[cfg(target_os = "linux")]
cpufeatures::new!(adx_bmi2, "adx", "bmi2");
cpufeatures::new!(avx512_ifma, "avx512f", "avx512dq", "avx512ifma");

/// Whether the CPU supports the ADX/BMI2 Montgomery multiplication kernel.
#[cfg(target_os = "linux")]
#[inline(always)]
pub(crate) fn has_adx() -> bool {
    !cfg!(bn254_disable = "adx") && adx_bmi2::get()
}

/// Whether the CPU and OS support the AVX-512 IFMA kernels.
#[inline(always)]
pub(crate) fn has_ifma() -> bool {
    !cfg!(bn254_disable = "ifma") && avx512_ifma::get()
}
