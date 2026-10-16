//! Differential testing of [`VerificationKey::verify_dalek`] (the
//! pre-SIMD-0376 rule) against [`VerificationKey::verify_simd0376`].
//!
//! A validator running both rules side by side records every signature the
//! two did not both accept as a [`FailureRecord`]. The `dual_verify_replay`
//! binary reads those records back, re-runs both rules, and reports any
//! disagreement or any result that does not reproduce.

use {
    solana_ed25519::ed_sigs::{Error, Signature, VerificationKey},
    std::io::{self, Read},
};

/// Magic bytes at the start of every [`FailureRecord`].
pub const FAILURE_MAGIC: [u8; 4] = *b"DV1\0";

/// One-byte code for a verification result, as stored in [`FailureRecord`].
pub fn result_code(r: &Result<(), Error>) -> u8 {
    match r {
        Ok(()) => b'A',
        Err(Error::InvalidSignature) => b'R',
        Err(Error::MalformedPublicKey) => b'K',
        Err(Error::InvalidSliceLength) => b'L',
        Err(_) => b'X',
    }
}

/// Results of both verification rules on one signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub dalek: Result<(), Error>,
    pub simd0376: Result<(), Error>,
}

impl Outcome {
    /// True when one rule accepts and the other rejects.
    pub fn disagrees(&self) -> bool {
        self.dalek.is_ok() != self.simd0376.is_ok()
    }

    /// Result codes as `(dalek, simd0376)`.
    pub fn codes(&self) -> (u8, u8) {
        (result_code(&self.dalek), result_code(&self.simd0376))
    }
}

/// Runs both rules on `(pubkey, signature, msg)`. A public key that fails to
/// decode is reported as the same error for both rules.
pub fn verify_both(pubkey: &[u8], signature: &[u8; 64], msg: &[u8]) -> Outcome {
    let signature = Signature::from(*signature);
    match VerificationKey::try_from(pubkey) {
        Ok(vk) => Outcome {
            dalek: vk.verify_dalek(&signature, msg),
            simd0376: vk.verify_simd0376(&signature, msg),
        },
        Err(err) => Outcome {
            dalek: Err(err),
            simd0376: Err(err),
        },
    }
}

/// A signature that the two rules did not both accept, with everything
/// needed to reproduce it. All integers are little-endian:
///
/// ```text
/// magic         [u8; 4]  b"DV1\0"
/// unix_us       u64
/// dalek         u8       result code, see `result_code`
/// simd0376      u8       result code
/// first         u8       b'D' or b'S': which rule ran first
/// thread_len    u8,  thread [u8; thread_len]
/// decompress_ns u32, dalek_ns u32, simd0376_ns u32
/// pubkey_len    u16, pubkey [u8; pubkey_len]
/// signature     [u8; 64]
/// msg_len       u32, msg [u8; msg_len]
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureRecord {
    pub unix_us: u64,
    pub dalek: u8,
    pub simd0376: u8,
    pub first: u8,
    pub thread: String,
    pub decompress_ns: u32,
    pub dalek_ns: u32,
    pub simd0376_ns: u32,
    pub pubkey: Vec<u8>,
    pub signature: [u8; 64],
    pub msg: Vec<u8>,
}

impl FailureRecord {
    /// Appends the encoded record to `out`. `thread` is truncated to 255
    /// bytes and `pubkey` to `u16::MAX` bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let thread = &self.thread.as_bytes()[..self.thread.len().min(u8::MAX as usize)];
        let pubkey = &self.pubkey[..self.pubkey.len().min(u16::MAX as usize)];
        let msg_len = u32::try_from(self.msg.len()).expect("message longer than u32::MAX");
        out.extend_from_slice(&FAILURE_MAGIC);
        out.extend_from_slice(&self.unix_us.to_le_bytes());
        out.extend_from_slice(&[self.dalek, self.simd0376, self.first, thread.len() as u8]);
        out.extend_from_slice(thread);
        out.extend_from_slice(&self.decompress_ns.to_le_bytes());
        out.extend_from_slice(&self.dalek_ns.to_le_bytes());
        out.extend_from_slice(&self.simd0376_ns.to_le_bytes());
        out.extend_from_slice(&(pubkey.len() as u16).to_le_bytes());
        out.extend_from_slice(pubkey);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&msg_len.to_le_bytes());
        out.extend_from_slice(&self.msg);
    }

    /// Reads the next record, or `Ok(None)` at a clean end of input.
    pub fn decode<R: Read>(r: &mut R) -> io::Result<Option<Self>> {
        let mut magic = [0u8; 4];
        match r.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        if magic != FAILURE_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        let unix_us = u64::from_le_bytes(read_array(r)?);
        let [dalek, simd0376, first, thread_len] = read_array(r)?;
        let thread = read_vec(r, thread_len as usize)?;
        let decompress_ns = u32::from_le_bytes(read_array(r)?);
        let dalek_ns = u32::from_le_bytes(read_array(r)?);
        let simd0376_ns = u32::from_le_bytes(read_array(r)?);
        let pubkey_len = u16::from_le_bytes(read_array(r)?);
        let pubkey = read_vec(r, pubkey_len as usize)?;
        let signature = read_array(r)?;
        let msg_len = u32::from_le_bytes(read_array(r)?);
        let msg = read_vec(r, msg_len as usize)?;
        Ok(Some(Self {
            unix_us,
            dalek,
            simd0376,
            first,
            thread: String::from_utf8_lossy(&thread).into_owned(),
            decompress_ns,
            dalek_ns,
            simd0376_ns,
            pubkey,
            signature,
            msg,
        }))
    }

    /// Re-runs both rules on the recorded inputs.
    pub fn replay(&self) -> Outcome {
        verify_both(&self.pubkey, &self.signature, &self.msg)
    }

    /// True when replaying gives the same result codes that were recorded.
    pub fn reproduces(&self, outcome: &Outcome) -> bool {
        outcome.codes() == (self.dalek, self.simd0376)
    }
}

fn read_array<R: Read, const N: usize>(r: &mut R) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_vec<R: Read>(r: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        sha2::{Digest, Sha512},
        solana_ed25519::{
            ed_sigs::SMALL_ORDER_ENCODINGS,
            edwards::{CompressedEdwardsY, EdwardsPoint},
            scalar::Scalar,
        },
    };

    /// Signs `msg` with secret scalar `a` and nonce `k`, adding the
    /// small-order point `t` to `R`. For a non-identity `t` the cofactored
    /// SIMD-0376 equation still holds but the cofactorless dalek one does not.
    fn sign_with_torsion(
        a: Scalar,
        k: Scalar,
        t: EdwardsPoint,
        msg: &[u8],
    ) -> ([u8; 32], [u8; 64]) {
        let pubkey = EdwardsPoint::mul_base(&a).compress().to_bytes();
        let r = (EdwardsPoint::mul_base(&k) + t).compress().to_bytes();
        let h = Sha512::new()
            .chain_update(r)
            .chain_update(pubkey)
            .chain_update(msg)
            .finalize();
        let h = Scalar::from_bytes_mod_order_wide(&h.into());
        let s = k + h * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(s.as_bytes());
        (pubkey, sig)
    }

    fn small_order(i: usize) -> EdwardsPoint {
        CompressedEdwardsY(SMALL_ORDER_ENCODINGS[i])
            .decompress()
            .unwrap()
    }

    const MSG: &[u8] = b"dual verify";

    fn keys() -> (Scalar, Scalar) {
        (
            Scalar::from_bytes_mod_order([7u8; 32]),
            Scalar::from_bytes_mod_order([9u8; 32]),
        )
    }

    #[test]
    fn test_valid_signature_both_accept() {
        let (a, k) = keys();
        // SMALL_ORDER_ENCODINGS[2] is the identity, so R is unmodified.
        let (pubkey, sig) = sign_with_torsion(a, k, small_order(2), MSG);
        let outcome = verify_both(&pubkey, &sig, MSG);
        assert_eq!(outcome.codes(), (b'A', b'A'));
        assert!(!outcome.disagrees());
    }

    #[test]
    fn test_torsioned_r_disagrees() {
        let (a, k) = keys();
        // Every non-identity small-order point: order 2, 4 and 8.
        for i in [0, 1, 3, 4, 5, 6, 7] {
            let (pubkey, sig) = sign_with_torsion(a, k, small_order(i), MSG);
            let outcome = verify_both(&pubkey, &sig, MSG);
            assert_eq!(outcome.codes(), (b'R', b'A'), "torsion point {i}");
            assert!(outcome.disagrees());
        }
    }

    #[test]
    fn test_malformed_pubkey_rejected_by_both() {
        // Off-curve point (from solana-signature's tests).
        let mut pubkey = [0u8; 32];
        pubkey[0] = 2;
        let outcome = verify_both(&pubkey, &[0u8; 64], MSG);
        assert_eq!(outcome.codes(), (b'K', b'K'));
        assert!(!outcome.disagrees());
    }

    #[test]
    fn test_record_round_trip_and_replay() {
        let (a, k) = keys();
        let (pubkey, sig) = sign_with_torsion(a, k, small_order(7), MSG);
        let records = [
            FailureRecord {
                unix_us: 1_792_016_885_332_708,
                dalek: b'R',
                simd0376: b'A',
                first: b'D',
                thread: "solReplayVer22".into(),
                decompress_ns: 14_730,
                dalek_ns: 86_098,
                simd0376_ns: 61_475,
                pubkey: pubkey.to_vec(),
                signature: sig,
                msg: MSG.to_vec(),
            },
            FailureRecord {
                unix_us: 1,
                dalek: b'A',
                simd0376: b'A',
                first: b'S',
                thread: String::new(),
                decompress_ns: 0,
                dalek_ns: 0,
                simd0376_ns: 0,
                pubkey: pubkey.to_vec(),
                signature: sig,
                msg: Vec::new(),
            },
        ];
        let mut bytes = Vec::new();
        for rec in &records {
            rec.encode(&mut bytes);
        }

        let mut reader = bytes.as_slice();
        let first = FailureRecord::decode(&mut reader).unwrap().unwrap();
        assert_eq!(first, records[0]);
        assert!(first.reproduces(&first.replay()));
        assert!(first.replay().disagrees());

        // Recorded as both-accept but the message differs: does not reproduce.
        let second = FailureRecord::decode(&mut reader).unwrap().unwrap();
        assert_eq!(second, records[1]);
        assert!(!second.reproduces(&second.replay()));

        assert!(FailureRecord::decode(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_decode_rejects_bad_input() {
        assert_eq!(
            FailureRecord::decode(&mut &b"XXXX"[..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&FAILURE_MAGIC);
        truncated.extend_from_slice(&[0u8; 3]);
        assert_eq!(
            FailureRecord::decode(&mut truncated.as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
