//! Differential testing of three Ed25519 verifiers:
//!
//! * `dalek`: [`VerificationKey::verify_dalek`] from solana-ed25519, the
//!   pre-SIMD-0376 rule;
//! * `simd0376`: [`VerificationKey::verify_simd0376`] from solana-ed25519;
//! * `ed25519_dalek`: `VerifyingKey::verify_strict` from the ed25519-dalek
//!   crate, the implementation `verify_dalek` is meant to match.
//!
//! A validator running all three side by side records every signature they
//! did not all accept as a [`FailureRecord`]. The `triple_verify_replay`
//! binary reads those records back, re-runs all three, and reports any
//! disagreement or any result that does not reproduce.

use {
    solana_ed25519::ed_sigs::{Error, Signature, VerificationKey},
    std::io::{self, Read},
};

/// Magic bytes of the current [`FailureRecord`] encoding.
pub const FAILURE_MAGIC: [u8; 4] = *b"TV1\0";
/// Magic bytes of the earlier two-verifier encoding, still accepted by
/// [`FailureRecord::decode`].
pub const DUAL_FAILURE_MAGIC: [u8; 4] = *b"DV1\0";
/// Result code for a verifier that was not run (records from the two-verifier
/// encoding have no `ed25519_dalek` result).
pub const NOT_RUN: u8 = b'-';

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

/// Parses a public key with ed25519-dalek. Failures map to
/// [`Error::MalformedPublicKey`], so codes line up with solana-ed25519's.
pub fn ed25519_dalek_key(pubkey: &[u8]) -> Result<ed25519_dalek::VerifyingKey, Error> {
    let bytes: &[u8; 32] = pubkey.try_into().map_err(|_| Error::MalformedPublicKey)?;
    ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| Error::MalformedPublicKey)
}

/// `verify_strict` with ed25519-dalek. Failures map to
/// [`Error::InvalidSignature`].
pub fn ed25519_dalek_verify(
    key: &ed25519_dalek::VerifyingKey,
    signature: &[u8; 64],
    msg: &[u8],
) -> Result<(), Error> {
    key.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| Error::InvalidSignature)
}

/// Results of all three verifiers on one signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub dalek: Result<(), Error>,
    pub simd0376: Result<(), Error>,
    pub ed25519_dalek: Result<(), Error>,
}

impl Outcome {
    /// True when the verifiers do not all accept or all reject.
    pub fn disagrees(&self) -> bool {
        let dalek = self.dalek.is_ok();
        dalek != self.simd0376.is_ok() || dalek != self.ed25519_dalek.is_ok()
    }

    /// Result codes as `(dalek, simd0376, ed25519_dalek)`.
    pub fn codes(&self) -> (u8, u8, u8) {
        (
            result_code(&self.dalek),
            result_code(&self.simd0376),
            result_code(&self.ed25519_dalek),
        )
    }
}

/// Runs all three verifiers on `(pubkey, signature, msg)`.
pub fn verify_all(pubkey: &[u8], signature: &[u8; 64], msg: &[u8]) -> Outcome {
    let sig = Signature::from(*signature);
    let (dalek, simd0376) = match VerificationKey::try_from(pubkey) {
        Ok(vk) => (vk.verify_dalek(&sig, msg), vk.verify_simd0376(&sig, msg)),
        Err(err) => (Err(err), Err(err)),
    };
    let ed25519_dalek =
        ed25519_dalek_key(pubkey).and_then(|key| ed25519_dalek_verify(&key, signature, msg));
    Outcome {
        dalek,
        simd0376,
        ed25519_dalek,
    }
}

/// A signature that the three verifiers did not all accept, with everything
/// needed to reproduce it. All integers are little-endian:
///
/// ```text
/// magic                       [u8; 4]  b"TV1\0"
/// unix_us                     u64
/// dalek, simd0376, ed25519_dalek
///                             [u8; 3]  result codes, see `result_code`
/// order                       [u8; 3]  run order, e.g. b"SED": simd0376,
///                                      ed25519_dalek, dalek
/// thread_len                  u8,  thread [u8; thread_len]
/// decompress_ns               u32      solana-ed25519 key decompression
/// ed25519_dalek_decompress_ns u32      ed25519-dalek key decompression
/// dalek_ns, simd0376_ns, ed25519_dalek_ns
///                             u32 each, verification only
/// pubkey_len                  u16, pubkey [u8; pubkey_len]
/// signature                   [u8; 64]
/// msg_len                     u32, msg [u8; msg_len]
/// ```
///
/// [`FailureRecord::decode`] also reads the earlier `b"DV1\0"` encoding,
/// which has no ed25519-dalek fields; those decode as [`NOT_RUN`] and 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureRecord {
    pub unix_us: u64,
    pub dalek: u8,
    pub simd0376: u8,
    pub ed25519_dalek: u8,
    pub order: [u8; 3],
    pub thread: String,
    pub decompress_ns: u32,
    pub ed25519_dalek_decompress_ns: u32,
    pub dalek_ns: u32,
    pub simd0376_ns: u32,
    pub ed25519_dalek_ns: u32,
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
        out.extend_from_slice(&[self.dalek, self.simd0376, self.ed25519_dalek]);
        out.extend_from_slice(&self.order);
        out.push(thread.len() as u8);
        out.extend_from_slice(thread);
        for ns in [
            self.decompress_ns,
            self.ed25519_dalek_decompress_ns,
            self.dalek_ns,
            self.simd0376_ns,
            self.ed25519_dalek_ns,
        ] {
            out.extend_from_slice(&ns.to_le_bytes());
        }
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
        let triple = match magic {
            FAILURE_MAGIC => true,
            DUAL_FAILURE_MAGIC => false,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic")),
        };
        let unix_us = u64::from_le_bytes(read_array(r)?);
        let read_u32 = |r: &mut R| read_array(r).map(u32::from_le_bytes);
        let (dalek, simd0376, ed25519_dalek, order, thread_len);
        if triple {
            [dalek, simd0376, ed25519_dalek] = read_array(r)?;
            order = read_array(r)?;
            [thread_len] = read_array(r)?;
        } else {
            let first;
            [dalek, simd0376, first, thread_len] = read_array(r)?;
            ed25519_dalek = NOT_RUN;
            order = if first == b'D' { *b"DS-" } else { *b"SD-" };
        }
        let thread = read_vec(r, thread_len as usize)?;
        let decompress_ns = read_u32(r)?;
        let ed25519_dalek_decompress_ns = if triple { read_u32(r)? } else { 0 };
        let dalek_ns = read_u32(r)?;
        let simd0376_ns = read_u32(r)?;
        let ed25519_dalek_ns = if triple { read_u32(r)? } else { 0 };
        let pubkey_len = u16::from_le_bytes(read_array(r)?);
        let pubkey = read_vec(r, pubkey_len as usize)?;
        let signature = read_array(r)?;
        let msg_len = read_u32(r)?;
        let msg = read_vec(r, msg_len as usize)?;
        Ok(Some(Self {
            unix_us,
            dalek,
            simd0376,
            ed25519_dalek,
            order,
            thread: String::from_utf8_lossy(&thread).into_owned(),
            decompress_ns,
            ed25519_dalek_decompress_ns,
            dalek_ns,
            simd0376_ns,
            ed25519_dalek_ns,
            pubkey,
            signature,
            msg,
        }))
    }

    /// Re-runs all three verifiers on the recorded inputs.
    pub fn replay(&self) -> Outcome {
        verify_all(&self.pubkey, &self.signature, &self.msg)
    }

    /// True when replaying gives the recorded result codes. A verifier that
    /// was not run when recording is not compared.
    pub fn reproduces(&self, outcome: &Outcome) -> bool {
        let (dalek, simd0376, ed25519_dalek) = outcome.codes();
        dalek == self.dalek
            && simd0376 == self.simd0376
            && (self.ed25519_dalek == NOT_RUN || ed25519_dalek == self.ed25519_dalek)
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
    /// SIMD-0376 equation still holds but the cofactorless strict one does
    /// not.
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
    fn test_valid_signature_all_accept() {
        let (a, k) = keys();
        // SMALL_ORDER_ENCODINGS[2] is the identity, so R is unmodified.
        let (pubkey, sig) = sign_with_torsion(a, k, small_order(2), MSG);
        let outcome = verify_all(&pubkey, &sig, MSG);
        assert_eq!(outcome.codes(), (b'A', b'A', b'A'));
        assert!(!outcome.disagrees());
    }

    #[test]
    fn test_torsioned_r_only_simd0376_accepts() {
        let (a, k) = keys();
        // Every non-identity small-order point: order 2, 4 and 8.
        for i in [0, 1, 3, 4, 5, 6, 7] {
            let (pubkey, sig) = sign_with_torsion(a, k, small_order(i), MSG);
            let outcome = verify_all(&pubkey, &sig, MSG);
            assert_eq!(outcome.codes(), (b'R', b'A', b'R'), "torsion point {i}");
            assert!(outcome.disagrees());
        }
    }

    #[test]
    fn test_malformed_pubkey_rejected_by_all() {
        let mut pubkey = [0u8; 32];
        pubkey[0] = 2;
        let outcome = verify_all(&pubkey, &[0u8; 64], MSG);
        assert_eq!(outcome.codes(), (b'K', b'K', b'K'));
        assert!(!outcome.disagrees());

        // Wrong length is a malformed key for ed25519-dalek too.
        let outcome = verify_all(&[0u8; 31], &[0u8; 64], MSG);
        assert_eq!(outcome.codes().2, b'K');
    }

    fn record(pubkey: [u8; 32], sig: [u8; 64], msg: &[u8]) -> FailureRecord {
        FailureRecord {
            unix_us: 1_792_016_885_332_708,
            dalek: b'R',
            simd0376: b'A',
            ed25519_dalek: b'R',
            order: *b"SED",
            thread: "solReplayVer22".into(),
            decompress_ns: 14_730,
            ed25519_dalek_decompress_ns: 15_002,
            dalek_ns: 86_098,
            simd0376_ns: 61_475,
            ed25519_dalek_ns: 90_210,
            pubkey: pubkey.to_vec(),
            signature: sig,
            msg: msg.to_vec(),
        }
    }

    #[test]
    fn test_record_round_trip_and_replay() {
        let (a, k) = keys();
        let (pubkey, sig) = sign_with_torsion(a, k, small_order(7), MSG);
        let first = record(pubkey, sig, MSG);
        // Same recorded codes, but the empty message changes the replay
        // result: does not reproduce.
        let second = record(pubkey, sig, b"");
        let mut bytes = Vec::new();
        first.encode(&mut bytes);
        second.encode(&mut bytes);

        let mut reader = bytes.as_slice();
        let decoded = FailureRecord::decode(&mut reader).unwrap().unwrap();
        assert_eq!(decoded, first);
        assert!(decoded.reproduces(&decoded.replay()));
        assert!(decoded.replay().disagrees());

        let decoded = FailureRecord::decode(&mut reader).unwrap().unwrap();
        assert_eq!(decoded, second);
        assert!(!decoded.reproduces(&decoded.replay()));

        assert!(FailureRecord::decode(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_decodes_dual_verify_records() {
        let (a, k) = keys();
        let (pubkey, sig) = sign_with_torsion(a, k, small_order(7), MSG);
        // A record as written by the earlier two-verifier logger.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DUAL_FAILURE_MAGIC);
        bytes.extend_from_slice(&7u64.to_le_bytes());
        bytes.extend_from_slice(&[b'R', b'A', b'S', 3]);
        bytes.extend_from_slice(b"thr");
        for ns in [1u32, 2, 3] {
            bytes.extend_from_slice(&ns.to_le_bytes());
        }
        bytes.extend_from_slice(&32u16.to_le_bytes());
        bytes.extend_from_slice(&pubkey);
        bytes.extend_from_slice(&sig);
        bytes.extend_from_slice(&(MSG.len() as u32).to_le_bytes());
        bytes.extend_from_slice(MSG);

        let decoded = FailureRecord::decode(&mut bytes.as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(
            (decoded.dalek, decoded.simd0376, decoded.ed25519_dalek),
            (b'R', b'A', NOT_RUN)
        );
        assert_eq!(decoded.order, *b"SD-");
        assert_eq!(
            (decoded.decompress_ns, decoded.dalek_ns, decoded.simd0376_ns),
            (1, 2, 3)
        );
        assert_eq!(decoded.thread, "thr");
        assert!(decoded.reproduces(&decoded.replay()));
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
