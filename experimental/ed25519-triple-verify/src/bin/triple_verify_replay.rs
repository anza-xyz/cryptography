//! Re-runs every record in triple-verify (or earlier dual-verify) failure
//! files through `verify_dalek`, `verify_simd0376` and ed25519-dalek's
//! `verify_strict`, and checks the results match what was recorded.
//!
//! ```text
//! cargo run --release -p ed25519-triple-verify --bin triple_verify_replay -- \
//!     [--dump] <failures.*.bin>...
//! ```
//!
//! Without `--dump`, only records that disagree or do not reproduce are
//! printed, followed by a summary line. Exits non-zero if any record
//! disagrees, does not reproduce, or a file is corrupt.

use {
    ed25519_triple_verify::FailureRecord,
    std::{fmt::Write as _, fs::File, io::BufReader, process::ExitCode},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn main() -> ExitCode {
    let mut dump = false;
    let mut files = Vec::new();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--dump" => dump = true,
            _ => files.push(arg),
        }
    }
    if files.is_empty() {
        eprintln!("usage: triple_verify_replay [--dump] <failures.*.bin>...");
        return ExitCode::from(2);
    }

    let (mut total, mut disagreements, mut not_reproduced, mut corrupt) = (0u64, 0u64, 0u64, 0u64);
    for path in files {
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("{path}: {err}");
                corrupt += 1;
                continue;
            }
        };
        let mut reader = BufReader::new(file);
        loop {
            let rec = match FailureRecord::decode(&mut reader) {
                Ok(Some(rec)) => rec,
                Ok(None) => break,
                Err(err) => {
                    eprintln!("{path}: stopped at corrupt or truncated record: {err}");
                    corrupt += 1;
                    break;
                }
            };
            total += 1;
            let outcome = rec.replay();
            let (dc, sc, ec) = outcome.codes();
            let disagrees = outcome.disagrees();
            let reproduced = rec.reproduces(&outcome);
            disagreements += u64::from(disagrees);
            not_reproduced += u64::from(!reproduced);
            if dump || disagrees || !reproduced {
                println!(
                    "{}{}unix_us={} thread={} order={} recorded(dalek/simd/ed25519-dalek)={}{}{} \
                     replay={}{}{} ns(dec/ed-dec/dalek/simd/ed25519-dalek)={}/{}/{}/{}/{} \
                     pubkey={} sig={} msg_len={}{}",
                    if disagrees { "MISMATCH " } else { "" },
                    if reproduced { "" } else { "NOT-REPRODUCED " },
                    rec.unix_us,
                    rec.thread,
                    String::from_utf8_lossy(&rec.order),
                    rec.dalek as char,
                    rec.simd0376 as char,
                    rec.ed25519_dalek as char,
                    dc as char,
                    sc as char,
                    ec as char,
                    rec.decompress_ns,
                    rec.ed25519_dalek_decompress_ns,
                    rec.dalek_ns,
                    rec.simd0376_ns,
                    rec.ed25519_dalek_ns,
                    hex(&rec.pubkey),
                    hex(&rec.signature),
                    rec.msg.len(),
                    if dump {
                        format!(" msg={}", hex(&rec.msg))
                    } else {
                        String::new()
                    },
                );
            }
        }
    }
    println!(
        "records={total} mismatches={disagreements} not_reproduced={not_reproduced} \
         corrupt_files={corrupt}"
    );
    if disagreements + not_reproduced + corrupt > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
