// functions are used in small_order but not recognized as such?
#![allow(dead_code)]
#![cfg(feature = "std")]

use crate::ed_sigs as ed25519_heea_zip215;
use crate::edwards::{CompressedEdwardsY, EdwardsPoint};
use color_eyre::{Report, eyre::eyre};

use core::convert::TryFrom;
use std::vec::Vec;

pub(crate) use crate::ed_sigs::verification_key::LEGACY_EXCLUDED_R_ENCODINGS as EXCLUDED_POINT_ENCODINGS;

pub struct TestCase {
    pub vk_bytes: [u8; 32],
    pub sig_bytes: [u8; 64],
    pub valid_legacy: bool,
    pub valid_zip215: bool,
}

impl core::fmt::Debug for TestCase {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_struct("TestCase")
            .field("vk_bytes", &hex::encode(&self.vk_bytes[..]))
            .field("sig_bytes", &hex::encode(&self.sig_bytes[..]))
            .field("valid_legacy", &self.valid_legacy)
            .field("valid_zip215", &self.valid_zip215)
            .finish()
    }
}

impl TestCase {
    pub fn check(&self) -> Result<(), Report> {
        match (self.valid_legacy, self.check_legacy()) {
            (false, Err(_)) => Ok(()),
            (true, Ok(())) => Ok(()),
            (false, Ok(())) => Err(eyre!(
                "legacy-invalid signature case validated under legacy rules"
            )),
            (true, Err(e)) => {
                Err(e.wrap_err("legacy-valid signature case was rejected under legacy rules"))
            }
        }?;
        match (self.valid_zip215, self.check_zip215()) {
            (false, Err(_)) => Ok(()),
            (true, Ok(())) => Ok(()),
            (false, Ok(())) => Err(eyre!(
                "zip215-invalid signature case validated under zip215 rules"
            )),
            (true, Err(e)) => {
                Err(e.wrap_err("zip215-valid signature case was rejected under zip215 rules"))
            }
        }
    }

    fn check_legacy(&self) -> Result<(), Report> {
        use ed25519_heea_zip215::{Signature, VerificationKey};
        let sig = Signature::from(self.sig_bytes);
        VerificationKey::try_from(self.vk_bytes).and_then(|vk| vk.verify_dalek(&sig, b"Zcash"))?;
        Ok(())
    }

    fn check_zip215(&self) -> Result<(), Report> {
        use ed25519_heea_zip215::{Signature, VerificationKey};
        let sig = Signature::from(self.sig_bytes);
        VerificationKey::try_from(self.vk_bytes).and_then(|vk| vk.verify(&sig, b"Zcash"))?;
        Ok(())
    }
}

pub fn non_canonical_field_encodings() -> Vec<[u8; 32]> {
    // There are 19 finite field elements which can be represented
    // non-canonically as x + p with x + p fitting in 255 bits:
    let mut bytes = [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];
    let mut encodings = Vec::new();
    for i in 0..19u8 {
        bytes[0] = 237 + i;
        encodings.push(bytes);
    }
    encodings
}

// Compute all 25 non-canonical point encodings.  The first 5 are low order.
pub fn non_canonical_point_encodings() -> Vec<[u8; 32]> {
    // Points are encoded by the y-coordinate and a bit indicating the
    // sign of the x-coordinate. There are two ways to construct a
    // non-canonical point encoding:
    //
    // (1) by using a non-canonical encoding of y (cf RFC8032§5.1.3.1)
    // (2) by selecting y so that both sign choices give the same x.
    //
    // Condition (1) can occur only for 19 field elements that can be encoded
    // non-canonically as y + p with y + p fitting in 255 bits.
    //
    // Condition (2) occurs if and only if x = -x, i.e., x = 0.
    // The curve equation is ax^2 + y^2 = 1 + dx^2 + y^2 so x = 0 => y^2 = 1.
    // This means y = 1 or y = -1.
    //
    // When y = -1, y can only be canonically encoded, so the encodings of (0,-1) are:
    // * enc(-1) || 0 [canonical]
    // * enc(-1) || 1 [non-canonical]
    //
    // When y = 1, y can be non-canonically encoded, so the encodings of (0,1) are:
    // * enc(1) || 0 [canonical]
    // * enc(1) || 1 [non-canonical]
    // * enc(2^255 - 18) || 0 [non-canonical]
    // * enc(2^255 - 18) || 1 [non-canonical]
    //
    // We pick up the latter two in generation of non-canonically encoded field elements,
    // and construct the first two explicitly.
    //
    // RFC8032§5.1.3.4 requires implementations to perform a field element equality check
    // on the x value computed inside the decompression routine and abort if x = 0 and
    // the sign bit was set.  However, no implementations do this, and any implementation
    // that did would then be subtly incompatible with others in a new and different way.
    //
    // (This taxonomy was created with pointers from Sean Bowe and NCC Group).
    let mut encodings = Vec::new();

    // Canonical y with non-canonical sign bits.
    let y1_noncanonical_sign_bit = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128,
    ];
    encodings.push(y1_noncanonical_sign_bit);
    let ym1_noncanonical_sign_bit = [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];
    encodings.push(ym1_noncanonical_sign_bit);

    // Run through non-canonical field elements.
    // Not all field elements are x-coordinates of curve points, so check:
    for mut x in non_canonical_field_encodings().into_iter() {
        if CompressedEdwardsY(x).decompress().is_some() {
            encodings.push(x);
        }
        x[31] |= 128;
        if CompressedEdwardsY(x).decompress().is_some() {
            encodings.push(x);
        }
    }

    // Check that all of the non-canonical points are really non-canonical
    for &e in &encodings {
        assert_ne!(
            e,
            CompressedEdwardsY(e)
                .decompress()
                .unwrap()
                .compress()
                .to_bytes()
        );
    }

    encodings
}

// Running this reveals that only the first 6 entries on the list have low order.
#[test]
fn print_non_canonical_points() {
    for encoding in non_canonical_point_encodings().into_iter() {
        let point = CompressedEdwardsY(encoding).decompress().unwrap();
        println!(
            "encoding {} has order {}",
            hex::encode(&encoding[..]),
            order(point)
        );
    }
}

pub fn order(point: EdwardsPoint) -> &'static str {
    use crate::traits::IsIdentity;
    if point.is_small_order() {
        let point2 = point + point;
        let point4 = point2 + point2;
        if point.is_identity() {
            "1"
        } else if point2.is_identity() {
            "2"
        } else if point4.is_identity() {
            "4"
        } else {
            "8"
        }
    } else if point.is_torsion_free() {
        "p"
    } else {
        ">p"
    }
}

#[test]
fn find_valid_excluded_encodings() {
    for (i, encoding) in EXCLUDED_POINT_ENCODINGS.iter().enumerate() {
        if let Some(point) = CompressedEdwardsY(*encoding).decompress() {
            println!("index {} is valid point of order {}", i, order(point));
        } else {
            println!("index {} is not a valid encoding", i);
        }
    }
}
