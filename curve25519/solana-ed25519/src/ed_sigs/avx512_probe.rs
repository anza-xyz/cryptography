cfg_if::cfg_if! {
    if #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx512f",
        target_feature = "avx512dq",
        target_feature = "avx512ifma",
    ))] {
        compile_error!("This should probably error, but the CI will not catch it");
    }
}
