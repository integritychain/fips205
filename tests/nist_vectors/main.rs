//! NIST ACVP SLH-DSA sample vectors.
//!
//! Pinned to ACVP-Server commit `975de31eb83d87039ec88934fdc47d8c312b892d`
//! (the same commit fips204 pins). `vsId` 53, `isSample: true`. The files are
//! gzip -9 `internalProjection.json.gz` only.
//!
//! External pre-hash groups (`preHash == "preHash"`) are counted and skipped
//! until the digest-and-OID API in plan section 6. Do not hash them here.
//!
//! ```text
//! FIPS205_NIST_SMOKE=1 cargo test --release --test nist_vectors
//! cargo test --release --test nist_vectors
//! ```
//!
//! `FIPS205_NIST_SMOKE=1` keeps every keygen case; per parameter set, one
//! deterministic pure-external sign, one hedged pure-external sign, one
//! deterministic internal sign, and the matching verify cases; all twelve
//! `hashAlg` values, both deterministic and hedged, on `SLH-DSA-SHA2-128s`
//! (skipped until section 6, but counted); one of each sigVer `reason` on
//! SHA2-128s; one valid external verify on every other set; and one valid
//! internal verify per set. The per-set pure-external pick includes the
//! 256-bit sets. Unset, the harness runs the full file.

use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;

use flate2::read::GzDecoder;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;

struct TestRng {
    data: Vec<Vec<u8>>,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }
    fn next_u64(&mut self) -> u64 { unimplemented!() }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        let x = self.data.pop().expect("TestRng underrun");
        assert_eq!(out.len(), x.len(), "TestRng length");
        out.copy_from_slice(&x);
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

struct Tally {
    ran: usize,
    smoke_skipped: usize,
    /// External pre-hash cases, waiting on plan section 6.
    prehash_skipped: usize,
    feature_skipped: usize,
}

impl Tally {
    fn new() -> Self {
        Self { ran: 0, smoke_skipped: 0, prehash_skipped: 0, feature_skipped: 0 }
    }

    fn report(&self, which: &str) {
        println!(
            "NIST {which}: ran {}, smoke-skipped {}, pre-hash skipped {} (plan section 6), feature-skipped {}",
            self.ran, self.smoke_skipped, self.prehash_skipped, self.feature_skipped
        );
    }
}

fn smoke() -> bool {
    std::env::var_os("FIPS205_NIST_SMOKE").is_some_and(|v| v == "1")
}

fn load(name: &str) -> Value {
    let path = format!(
        "{}/tests/nist_vectors/{name}/internalProjection.json.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let file = File::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    let dec = GzDecoder::new(BufReader::new(file));
    let doc: Value = serde_json::from_reader(dec).unwrap_or_else(|e| panic!("parse {path}: {e}"));
    assert_eq!(doc["vsId"].as_u64(), Some(53), "{name} vsId");
    assert_eq!(doc["isSample"].as_bool(), Some(true), "{name} isSample");
    doc
}

fn hex_field(v: &Value, key: &str, loc: &str) -> Vec<u8> {
    let s = v[key].as_str().unwrap_or_else(|| panic!("{loc} missing {key}"));
    hex::decode(s).unwrap_or_else(|e| panic!("{loc} {key}: {e}"))
}

fn copy_n<const N: usize>(bytes: &[u8], loc: &str, what: &str) -> [u8; N] {
    let mut out = [0u8; N];
    assert_eq!(bytes.len(), N, "{loc} {what} length {}, expected {N}", bytes.len());
    out.copy_from_slice(bytes);
    out
}

fn loc_of(set: &str, tg: u64, tc: u64) -> String {
    format!("{set} tgId={tg} tcId={tc}")
}

fn known_set(set: &str) -> bool {
    matches!(
        set,
        "SLH-DSA-SHA2-128s"
            | "SLH-DSA-SHA2-128f"
            | "SLH-DSA-SHA2-192s"
            | "SLH-DSA-SHA2-192f"
            | "SLH-DSA-SHA2-256s"
            | "SLH-DSA-SHA2-256f"
            | "SLH-DSA-SHAKE-128s"
            | "SLH-DSA-SHAKE-128f"
            | "SLH-DSA-SHAKE-192s"
            | "SLH-DSA-SHAKE-192f"
            | "SLH-DSA-SHAKE-256s"
            | "SLH-DSA-SHAKE-256f"
    )
}

fn note_unhandled(set: &str, tally: &mut Tally) {
    if known_set(set) {
        tally.feature_skipped += 1;
    } else {
        panic!("unknown parameter set {set}");
    }
}

macro_rules! keygen_one {
    ($m:ident, $test:expr, $loc:expr) => {{
        let sk_seed = copy_n::<{ fips205::$m::N }>(&hex_field($test, "skSeed", $loc), $loc, "skSeed");
        let sk_prf = copy_n::<{ fips205::$m::N }>(&hex_field($test, "skPrf", $loc), $loc, "skPrf");
        let pk_seed = copy_n::<{ fips205::$m::N }>(&hex_field($test, "pkSeed", $loc), $loc, "pkSeed");
        let (pk, sk) = <fips205::$m::KG as KeyGen>::keygen_with_seeds(&sk_seed, &sk_prf, &pk_seed);
        let pk_bytes = pk.into_bytes();
        let sk_bytes = sk.into_bytes();
        assert_eq!(pk_bytes.as_slice(), hex_field($test, "pk", $loc).as_slice(), "{loc} pk", loc = $loc);
        assert_eq!(sk_bytes.as_slice(), hex_field($test, "sk", $loc).as_slice(), "{loc} sk", loc = $loc);
    }};
}

macro_rules! sign_one {
    ($m:ident, $test:expr, $loc:expr, $internal:expr, $hedged:expr) => {{
        let sk_raw = hex_field($test, "sk", $loc);
        let sk_arr = copy_n::<{ fips205::$m::SK_LEN }>(&sk_raw, $loc, "sk");
        let sk = <fips205::$m::PrivateKey as SerDes>::try_from_bytes(&sk_arr)
            .unwrap_or_else(|e| panic!("{} {e}", $loc));
        let msg = hex_field($test, "message", $loc);
        let mut rng = TestRng { data: Vec::new() };
        if $hedged {
            let add = hex_field($test, "additionalRandomness", $loc);
            assert_eq!(add.len(), fips205::$m::N, "{} additionalRandomness", $loc);
            rng.data.push(add);
        }
        let sig = if $internal {
            sk.sign_internal(&mut rng, &msg, $hedged)
        } else {
            let ctx = hex_field($test, "context", $loc);
            sk.try_sign_with_rng(&mut rng, &msg, &ctx, $hedged)
        }
        .unwrap_or_else(|e| panic!("{} sign: {e}", $loc));
        assert_eq!(sig.as_slice(), hex_field($test, "signature", $loc).as_slice(), "{}", $loc);
    }};
}

macro_rules! verify_one {
    ($m:ident, $test:expr, $loc:expr, $internal:expr) => {{
        let pk_raw = hex_field($test, "pk", $loc);
        let pk_arr = copy_n::<{ fips205::$m::PK_LEN }>(&pk_raw, $loc, "pk");
        let pk = <fips205::$m::PublicKey as SerDes>::try_from_bytes(&pk_arr)
            .unwrap_or_else(|e| panic!("{} {e}", $loc));
        let msg = hex_field($test, "message", $loc);
        let sig_raw = hex_field($test, "signature", $loc);
        // Too-large and too-small signatures fail `try_into` to `[u8; SIG_LEN]`.
        // That is a verify failure; `verify` itself still takes a fixed array.
        let ok = match sig_raw.as_slice().try_into() {
            Ok(sig) => {
                if $internal {
                    pk.verify_internal(&msg, sig)
                } else {
                    let ctx = hex_field($test, "context", $loc);
                    pk.verify(&msg, sig, &ctx)
                }
            }
            Err(_) => false,
        };
        let expect = $test["testPassed"].as_bool().unwrap_or_else(|| panic!("{} testPassed", $loc));
        assert_eq!(ok, expect, "{}", $loc);
    }};
}

macro_rules! dispatch {
    ($set:expr, $mac:ident, $($arg:expr),*) => {
        match $set {
            #[cfg(feature = "slh_dsa_sha2_128s")]
            "SLH-DSA-SHA2-128s" => { $mac!(slh_dsa_sha2_128s, $($arg),*); true }
            #[cfg(feature = "slh_dsa_sha2_128f")]
            "SLH-DSA-SHA2-128f" => { $mac!(slh_dsa_sha2_128f, $($arg),*); true }
            #[cfg(feature = "slh_dsa_sha2_192s")]
            "SLH-DSA-SHA2-192s" => { $mac!(slh_dsa_sha2_192s, $($arg),*); true }
            #[cfg(feature = "slh_dsa_sha2_192f")]
            "SLH-DSA-SHA2-192f" => { $mac!(slh_dsa_sha2_192f, $($arg),*); true }
            #[cfg(feature = "slh_dsa_sha2_256s")]
            "SLH-DSA-SHA2-256s" => { $mac!(slh_dsa_sha2_256s, $($arg),*); true }
            #[cfg(feature = "slh_dsa_sha2_256f")]
            "SLH-DSA-SHA2-256f" => { $mac!(slh_dsa_sha2_256f, $($arg),*); true }
            #[cfg(feature = "slh_dsa_shake_128s")]
            "SLH-DSA-SHAKE-128s" => { $mac!(slh_dsa_shake_128s, $($arg),*); true }
            #[cfg(feature = "slh_dsa_shake_128f")]
            "SLH-DSA-SHAKE-128f" => { $mac!(slh_dsa_shake_128f, $($arg),*); true }
            #[cfg(feature = "slh_dsa_shake_192s")]
            "SLH-DSA-SHAKE-192s" => { $mac!(slh_dsa_shake_192s, $($arg),*); true }
            #[cfg(feature = "slh_dsa_shake_192f")]
            "SLH-DSA-SHAKE-192f" => { $mac!(slh_dsa_shake_192f, $($arg),*); true }
            #[cfg(feature = "slh_dsa_shake_256s")]
            "SLH-DSA-SHAKE-256s" => { $mac!(slh_dsa_shake_256s, $($arg),*); true }
            #[cfg(feature = "slh_dsa_shake_256f")]
            "SLH-DSA-SHAKE-256f" => { $mac!(slh_dsa_shake_256f, $($arg),*); true }
            _ => false,
        }
    };
}

fn str_field<'a>(v: &'a Value, key: &str, loc: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{loc} missing {key}"))
}

fn keep_siggen(set: &str, iface: &str, pre: &str, det: bool, idx: usize) -> bool {
    if !smoke() {
        return true;
    }
    // All twelve hash algorithms, both hedged and deterministic, on SHA2-128s.
    // Execution still skips them until plan section 6; the log counts that skip.
    if pre == "preHash" {
        return set == "SLH-DSA-SHA2-128s";
    }
    if iface == "external" && pre == "pure" && idx == 0 {
        return true;
    }
    iface == "internal" && pre == "none" && det && idx == 0
}

struct VerPick {
    reasons_128s: HashSet<String>,
    valid_external: HashSet<String>,
    valid_internal: HashSet<String>,
}

impl VerPick {
    fn keep(&mut self, set: &str, iface: &str, pre: &str, reason: &str, passed: bool) -> bool {
        if !smoke() {
            return true;
        }
        if pre == "preHash" {
            return false;
        }
        if set == "SLH-DSA-SHA2-128s" && iface == "external" && pre == "pure" {
            return self.reasons_128s.insert(reason.to_string());
        }
        if passed && iface == "external" && pre == "pure" {
            return self.valid_external.insert(set.to_string());
        }
        if passed && iface == "internal" && pre == "none" {
            return self.valid_internal.insert(set.to_string());
        }
        false
    }
}

#[test]
fn nist_keygen() {
    let doc = load("SLH-DSA-keyGen-FIPS205");
    let mut tally = Tally::new();
    for group in doc["testGroups"].as_array().expect("keyGen testGroups") {
        let set = str_field(group, "parameterSet", "keyGen group");
        let tg = group["tgId"].as_u64().expect("tgId");
        for test in group["tests"].as_array().expect("tests") {
            let tc = test["tcId"].as_u64().expect("tcId");
            let loc = loc_of(set, tg, tc);
            // Smoke keeps every keygen case.
            if !dispatch!(set, keygen_one, test, &loc) {
                note_unhandled(set, &mut tally);
                continue;
            }
            tally.ran += 1;
        }
    }
    tally.report("keyGen");
    assert!(tally.ran > 0, "no keygen cases ran");
}

#[test]
fn nist_siggen() {
    let doc = load("SLH-DSA-sigGen-FIPS205");
    let mut tally = Tally::new();
    for group in doc["testGroups"].as_array().expect("sigGen testGroups") {
        let set = str_field(group, "parameterSet", "sigGen group");
        let tg = group["tgId"].as_u64().expect("tgId");
        let iface = str_field(group, "signatureInterface", "sigGen group");
        let pre = str_field(group, "preHash", "sigGen group");
        let det = group["deterministic"].as_bool().expect("deterministic");
        let internal = iface == "internal";
        let hedged = !det;
        for (idx, test) in group["tests"].as_array().expect("tests").iter().enumerate() {
            let tc = test["tcId"].as_u64().expect("tcId");
            let loc = loc_of(set, tg, tc);
            if !keep_siggen(set, iface, pre, det, idx) {
                tally.smoke_skipped += 1;
                continue;
            }
            // External pre-hash waits on the digest-and-OID API (plan section 6).
            if pre == "preHash" {
                tally.prehash_skipped += 1;
                continue;
            }
            if !dispatch!(set, sign_one, test, &loc, internal, hedged) {
                note_unhandled(set, &mut tally);
                continue;
            }
            tally.ran += 1;
        }
    }
    tally.report("sigGen");
    assert!(tally.ran > 0, "no sigGen cases ran");
}

#[test]
fn nist_sigver() {
    let doc = load("SLH-DSA-sigVer-FIPS205");
    let mut tally = Tally::new();
    let mut pick = VerPick {
        reasons_128s: HashSet::new(),
        valid_external: HashSet::new(),
        valid_internal: HashSet::new(),
    };
    for group in doc["testGroups"].as_array().expect("sigVer testGroups") {
        let set = str_field(group, "parameterSet", "sigVer group");
        let tg = group["tgId"].as_u64().expect("tgId");
        let iface = str_field(group, "signatureInterface", "sigVer group");
        let pre = str_field(group, "preHash", "sigVer group");
        let internal = iface == "internal";
        for test in group["tests"].as_array().expect("tests") {
            let tc = test["tcId"].as_u64().expect("tcId");
            let loc = loc_of(set, tg, tc);
            let reason = test["reason"].as_str().unwrap_or("");
            let passed = test["testPassed"].as_bool().unwrap_or(false);
            if !pick.keep(set, iface, pre, reason, passed) {
                tally.smoke_skipped += 1;
                continue;
            }
            // External pre-hash waits on the digest-and-OID API (plan section 6).
            if pre == "preHash" {
                tally.prehash_skipped += 1;
                continue;
            }
            if !dispatch!(set, verify_one, test, &loc, internal) {
                note_unhandled(set, &mut tally);
                continue;
            }
            tally.ran += 1;
        }
    }
    tally.report("sigVer");
    assert!(tally.ran > 0, "no sigVer cases ran");
}
