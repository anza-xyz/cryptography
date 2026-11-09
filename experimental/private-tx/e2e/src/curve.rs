//! The embedded curve: gnark-crypto's twisted Edwards curve over BN254 Fr
//! (Baby Jubjub in `a = -1` form), enough of it for a wallet: point
//! arithmetic, scalar multiplication, the compressed encoding, and the
//! diversifier group hash. Mirrors `circuits/note` and `circuits/encrypt`.
//!
//! `a x² + y² = 1 + d x² y²`, `a = -1`.

use {
    crate::{domain_tag, poseidon},
    ark_bn254::Fr,
    ark_ff::{AdditiveGroup, BigInteger, Field, One, PrimeField, Zero},
};

/// An affine point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: Fr,
    pub y: Fr,
}

fn fr(s: &str) -> Fr {
    s.parse::<Fr>().expect("decimal field element")
}

/// Curve coefficient `d`; `a = -1`.
pub fn d() -> Fr {
    fr("12181644023421730124874158521699555681764249180949974110617291017600649128846")
}

/// The base point.
pub fn base() -> Point {
    Point {
        x: fr("9671717474070082183213120605117400219616337014328744928644933853176787189663"),
        y: fr("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    }
}

impl Point {
    pub const IDENTITY: Point = Point {
        x: Fr::ZERO,
        y: Fr::ONE,
    };

    pub fn is_on_curve(&self) -> bool {
        let (xx, yy) = (self.x * self.x, self.y * self.y);
        -xx + yy == Fr::one() + d() * xx * yy
    }

    /// Unified addition.
    pub fn add(&self, q: &Point) -> Point {
        let dxy = d() * self.x * q.x * self.y * q.y;
        let x = (self.x * q.y + self.y * q.x) / (Fr::one() + dxy);
        let y = (self.y * q.y + self.x * q.x) / (Fr::one() - dxy); // a = -1
        Point { x, y }
    }

    pub fn double(&self) -> Point {
        self.add(self)
    }

    /// `[s]P` for the integer `s`, double-and-add over its bits (the
    /// gadget's arithmetic: no reduction modulo the subgroup order).
    pub fn mul(&self, s: &Fr) -> Point {
        let mut acc = Point::IDENTITY;
        for bit in s.into_bigint().to_bits_be() {
            acc = acc.double();
            if bit {
                acc = acc.add(self);
            }
        }
        acc
    }

    /// gnark-crypto's compressed form (RFC 8032 style): `y` little-endian
    /// with the top bit of the last byte set when `x` is lexicographically
    /// largest (`x > (p - 1) / 2`).
    pub fn compress(&self) -> [u8; 32] {
        let mut out: [u8; 32] = self.y.into_bigint().to_bytes_le().try_into().unwrap();
        if lexicographically_largest(&self.x) {
            out[31] |= 0x80;
        }
        out
    }

    pub fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        let largest = bytes[31] & 0x80 != 0;
        let mut yb = *bytes;
        yb[31] &= 0x7f;
        let y = Fr::from_le_bytes_mod_order(&yb);
        if y.into_bigint().to_bytes_le() != yb {
            return None; // non-canonical
        }
        let mut x = x_from_y(&y)?;
        if lexicographically_largest(&x) != largest {
            x = -x;
        }
        Some(Point { x, y })
    }
}

/// `x > (p - 1) / 2`.
pub fn lexicographically_largest(x: &Fr) -> bool {
    let half = (-Fr::one()) * Fr::from(2u64).inverse().unwrap(); // (p - 1) / 2
    x.into_bigint() > half.into_bigint()
}

/// Either root `x` of the curve equation for `y`, if any.
pub fn x_from_y(y: &Fr) -> Option<Fr> {
    let yy = y * y;
    let num = Fr::one() - yy;
    let den = -Fr::one() - d() * yy;
    if den.is_zero() {
        return None;
    }
    (num / den).sqrt()
}

/// Tries the group hash makes before giving up on a diversifier, as the
/// circuits replay it (`note.GroupHashTries`).
pub const GROUP_HASH_TRIES: u64 = 8;

/// The diversifier group hash (`note.Diversifier.GroupHash`): the first
/// `x = Poseidon(GD, d, counter)` that is on the curve, smaller `y`,
/// cleared of the cofactor.
pub fn group_hash(d_bytes: &[u8; 11]) -> Option<Point> {
    let d_elem = Fr::from_be_bytes_mod_order(d_bytes);
    for ctr in 0u64..GROUP_HASH_TRIES {
        let x = Fr::from_be_bytes_mod_order(&poseidon(&[
            domain_tag("privtx/gd"),
            d_elem,
            Fr::from(ctr),
        ]));
        let xx = x * x;
        let num = Fr::one() + xx; // 1 - a x², a = -1
        let den = Fr::one() - d() * xx;
        if den.is_zero() {
            continue;
        }
        let Some(mut y) = (num / den).sqrt() else {
            continue;
        };
        let neg = -y;
        if neg.into_bigint() < y.into_bigint() {
            y = neg;
        }
        let p = Point { x, y }.mul(&Fr::from(8u64));
        if p == Point::IDENTITY {
            continue;
        }
        return Some(p);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_point_and_arithmetic() {
        let g = base();
        assert!(g.is_on_curve());
        assert!(g.double().is_on_curve());
        assert_eq!(g.add(&Point::IDENTITY), g);
        assert_eq!(g.mul(&Fr::from(3u64)), g.double().add(&g));
        let c = g.compress();
        assert_eq!(Point::decompress(&c), Some(g));
        let neg = Point { x: -g.x, y: g.y };
        assert_eq!(Point::decompress(&neg.compress()), Some(neg));
    }
}
