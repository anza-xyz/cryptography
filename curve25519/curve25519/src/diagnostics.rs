//! Build time diagnostics

// simd was assumed over overridden
#[cfg(curve25519_backend = "simd")]
compile_error!("curve25519_backend is 'simd'");

// 64 bits target_pointer_width was assumed or overridden
#[cfg(curve25519_bits = "64")]
compile_error!("curve25519_bits is '64'");
