//! Build time diagnostics

// simd was assumed or overridden
#[cfg(curve25519_backend = "simd")]
compile_error!("curve25519_backend is 'simd'");

// serial was assumed or overridden
#[cfg(curve25519_backend = "serial")]
compile_error!("curve25519_backend is 'serial'");

// 64 bits target_pointer_width was assumed or overridden
#[cfg(curve25519_bits = "64")]
compile_error!("curve25519_bits is '64'");
