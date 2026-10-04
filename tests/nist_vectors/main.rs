//! NIST ACVP SLH-DSA sample vectors.
//!
//! Pinned to ACVP-Server commit `975de31eb83d87039ec88934fdc47d8c312b892d`
//! (the same commit fips204 pins). `vsId` 53, `isSample: true`. The files are
//! gzip -9 `internalProjection.json.gz` only.
//!
//! External pre-hash groups (`preHash == "preHash"`) hash `message` here and
//! call `try_hash_sign_with_rng` / `hash_verify` with the digest and OID.
//!
//! ```text
//! FIPS205_NIST_SMOKE=1 cargo test --release --test nist_vectors
//! cargo test --release --test nist_vectors
//! ```
//!
//! `FIPS205_NIST_SMOKE=1` keeps every keygen case; per parameter set, one
//! deterministic pure-external sign, one hedged pure-external sign, one
//! deterministic internal sign, and the matching verify cases; all twelve
//! `hashAlg` values, both deterministic and hedged, on `SLH-DSA-SHA2-128s`;
//! one of each sigVer `reason` on SHA2-128s; one valid external verify on
//! every other set; and one valid internal verify per set. The per-set
//! pure-external pick includes the 256-bit sets. Unset, the harness runs the
//! full file.
//!
//! Every vector in each file is applied. Each test counts the cases in its file
//! and fails unless every one ran, apart from smoke mode and parameter sets whose
//! feature is off. A group field or group kind that this harness does not know
//! fails the test, so a new kind of NIST group is never skipped. The internal
//! groups call the `acvp-internal` hooks, which `cargo test` enables through the
//! dev-dependency on this crate in Cargo.toml. `cargo package` drops that
//! dev-dependency, so a test run from the published crate counts those groups
//! as skipped unless it passes `--features acvp-internal`.

// The `acvp-internal` hooks are deprecated so that nothing outside the tests calls them.
#![allow(deprecated)]

use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;

use flate2::read::GzDecoder;
use fips205::pre_hash;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

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
    total: usize,
    ran: usize,
    smoke_skipped: usize,
    feature_skipped: usize,
    hook_skipped: usize,
}

impl Tally {
    fn new(doc: &Value) -> Self {
        let total = groups(doc).iter().map(|g| cases(g).len()).sum();
        Self { total, ran: 0, smoke_skipped: 0, feature_skipped: 0, hook_skipped: 0 }
    }

    fn finish(&self, which: &str) {
        println!(
            "NIST {which}: ran {}, smoke-skipped {}, feature-skipped {}, of {}",
            self.ran, self.smoke_skipped, self.feature_skipped, self.total
        );
        if self.hook_skipped > 0 {
            println!(
                "NIST {which}: skipped {} internal cases; rerun with --features acvp-internal",
                self.hook_skipped
            );
        }
        assert_eq!(
            self.ran + self.smoke_skipped + self.feature_skipped + self.hook_skipped,
            self.total,
            "NIST {which}: some cases did not run"
        );
        assert!(self.ran > 0, "NIST {which}: no cases ran");
    }
}

fn groups(doc: &Value) -> &Vec<Value> {
    doc["testGroups"].as_array().expect("testGroups")
}

fn cases(group: &Value) -> &Vec<Value> {
    group["tests"].as_array().expect("tests")
}

/// Fails on a group field that this harness does not know, and on any `testType` but AFT.
fn check_group(group: &Value, known: &[&str]) {
    for key in group.as_object().expect("group").keys() {
        assert!(known.contains(&key.as_str()), "tgId {}: unknown group field {key}", group["tgId"]);
    }
    assert_eq!(group["testType"], "AFT", "tgId {}: testType", group["tgId"]);
}

/// Whether a sigGen or sigVer group uses the internal interface. Panics on a combination of
/// `signatureInterface` and `preHash` that this harness does not know.
fn is_internal(group: &Value) -> bool {
    match (group["signatureInterface"].as_str(), group["preHash"].as_str()) {
        (Some("external"), Some("pure" | "preHash")) => false,
        (Some("internal"), Some("none")) => true,
        other => panic!("tgId {}: unknown group kind {other:?}", group["tgId"]),
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

// The internal groups call the `acvp-internal` hooks, which exist only with that feature.
// Without it, those cases are counted as skipped before these are reached.
#[cfg(feature = "acvp-internal")]
macro_rules! sign_internal {
    ($sk:expr, $rng:expr, $msg:expr, $hedged:expr) => {
        $sk.sign_internal($rng, $msg, $hedged)
    };
}
#[cfg(not(feature = "acvp-internal"))]
macro_rules! sign_internal {
    ($($arg:tt)*) => {
        unreachable!("skipped without acvp-internal")
    };
}
#[cfg(feature = "acvp-internal")]
macro_rules! verify_internal {
    ($pk:expr, $msg:expr, $sig:expr) => {
        $pk.verify_internal($msg, $sig)
    };
}
#[cfg(not(feature = "acvp-internal"))]
macro_rules! verify_internal {
    ($($arg:tt)*) => {
        unreachable!("skipped without acvp-internal")
    };
}

macro_rules! keygen_one {
    ($m:ident, $test:expr, $loc:expr) => {{
        let sk_seed = copy_n::<{ fips205::$m::N }>(&hex_field($test, "skSeed", $loc), $loc, "skSeed");
        let sk_prf = copy_n::<{ fips205::$m::N }>(&hex_field($test, "skPrf", $loc), $loc, "skPrf");
        let pk_seed = copy_n::<{ fips205::$m::N }>(&hex_field($test, "pkSeed", $loc), $loc, "pkSeed");
        let (pk, sk) = <fips205::$m::KG as KeyGen>::keygen_from_seed(&sk_seed, &sk_prf, &pk_seed);
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
        let sk = <fips205::$m::PrivateKey as SerDes>::try_from_bytes(sk_arr)
            .unwrap_or_else(|e| panic!("{} {e}", $loc));
        let msg = hex_field($test, "message", $loc);
        let mut rng = TestRng { data: Vec::new() };
        if $hedged {
            let add = hex_field($test, "additionalRandomness", $loc);
            assert_eq!(add.len(), fips205::$m::N, "{} additionalRandomness", $loc);
            rng.data.push(add);
        }
        let sig = if $internal {
            sign_internal!(sk, &mut rng, &msg, $hedged)
        } else {
            let ctx = hex_field($test, "context", $loc);
            sk.try_sign_with_rng(&mut rng, &msg, &ctx, $hedged)
        }
        .unwrap_or_else(|e| panic!("{} sign: {e}", $loc));
        assert_eq!(sig.as_slice(), hex_field($test, "signature", $loc).as_slice(), "{}", $loc);
    }};
}

macro_rules! sign_hash {
    ($m:ident, $test:expr, $loc:expr, $hedged:expr) => {{
        let sk_raw = hex_field($test, "sk", $loc);
        let sk_arr = copy_n::<{ fips205::$m::SK_LEN }>(&sk_raw, $loc, "sk");
        let sk = <fips205::$m::PrivateKey as SerDes>::try_from_bytes(sk_arr)
            .unwrap_or_else(|e| panic!("{} {e}", $loc));
        let msg = hex_field($test, "message", $loc);
        let ctx = hex_field($test, "context", $loc);
        let (oid, digest) = ph_of(str_field($test, "hashAlg", $loc), &msg, $loc);
        let mut rng = TestRng { data: Vec::new() };
        if $hedged {
            let add = hex_field($test, "additionalRandomness", $loc);
            assert_eq!(add.len(), fips205::$m::N, "{} additionalRandomness", $loc);
            rng.data.push(add);
        }
        let sig = sk
            .try_hash_sign_with_rng(&mut rng, &digest, &ctx, oid, $hedged)
            .unwrap_or_else(|e| panic!("{} sign: {e}", $loc));
        assert_eq!(sig.as_slice(), hex_field($test, "signature", $loc).as_slice(), "{}", $loc);
    }};
}

macro_rules! verify_one {
    ($m:ident, $test:expr, $loc:expr, $internal:expr) => {{
        let pk_raw = hex_field($test, "pk", $loc);
        let pk_arr = copy_n::<{ fips205::$m::PK_LEN }>(&pk_raw, $loc, "pk");
        let pk = <fips205::$m::PublicKey as SerDes>::try_from_bytes(pk_arr)
            .unwrap_or_else(|e| panic!("{} {e}", $loc));
        let msg = hex_field($test, "message", $loc);
        let sig_raw = hex_field($test, "signature", $loc);
        // Too-large and too-small signatures fail `try_into` to `[u8; SIG_LEN]`.
        // That is a verify failure; `verify` itself still takes a fixed array.
        let ok = match sig_raw.as_slice().try_into() {
            Ok(sig) => {
                if $internal {
                    verify_internal!(pk, &msg, sig)
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

macro_rules! verify_hash {
    ($m:ident, $test:expr, $loc:expr) => {{
        let pk_raw = hex_field($test, "pk", $loc);
        let pk_arr = copy_n::<{ fips205::$m::PK_LEN }>(&pk_raw, $loc, "pk");
        let pk = <fips205::$m::PublicKey as SerDes>::try_from_bytes(pk_arr)
            .unwrap_or_else(|e| panic!("{} {e}", $loc));
        let msg = hex_field($test, "message", $loc);
        let ctx = hex_field($test, "context", $loc);
        let (oid, digest) = ph_of(str_field($test, "hashAlg", $loc), &msg, $loc);
        let sig_raw = hex_field($test, "signature", $loc);
        let ok = match sig_raw.as_slice().try_into() {
            Ok(sig) => pk.hash_verify(&digest, sig, &ctx, oid),
            Err(_) => false,
        };
        let expect = $test["testPassed"].as_bool().unwrap_or_else(|| panic!("{} testPassed", $loc));
        assert_eq!(ok, expect, "{}", $loc);
    }};
}

macro_rules! dispatch {
    ($set:expr, $mac:ident, $($arg:expr),*) => {
        match $set {
            #[cfg(feature = "slh-dsa-sha2-128s")]
            "SLH-DSA-SHA2-128s" => { $mac!(slh_dsa_sha2_128s, $($arg),*); true }
            #[cfg(feature = "slh-dsa-sha2-128f")]
            "SLH-DSA-SHA2-128f" => { $mac!(slh_dsa_sha2_128f, $($arg),*); true }
            #[cfg(feature = "slh-dsa-sha2-192s")]
            "SLH-DSA-SHA2-192s" => { $mac!(slh_dsa_sha2_192s, $($arg),*); true }
            #[cfg(feature = "slh-dsa-sha2-192f")]
            "SLH-DSA-SHA2-192f" => { $mac!(slh_dsa_sha2_192f, $($arg),*); true }
            #[cfg(feature = "slh-dsa-sha2-256s")]
            "SLH-DSA-SHA2-256s" => { $mac!(slh_dsa_sha2_256s, $($arg),*); true }
            #[cfg(feature = "slh-dsa-sha2-256f")]
            "SLH-DSA-SHA2-256f" => { $mac!(slh_dsa_sha2_256f, $($arg),*); true }
            #[cfg(feature = "slh-dsa-shake-128s")]
            "SLH-DSA-SHAKE-128s" => { $mac!(slh_dsa_shake_128s, $($arg),*); true }
            #[cfg(feature = "slh-dsa-shake-128f")]
            "SLH-DSA-SHAKE-128f" => { $mac!(slh_dsa_shake_128f, $($arg),*); true }
            #[cfg(feature = "slh-dsa-shake-192s")]
            "SLH-DSA-SHAKE-192s" => { $mac!(slh_dsa_shake_192s, $($arg),*); true }
            #[cfg(feature = "slh-dsa-shake-192f")]
            "SLH-DSA-SHAKE-192f" => { $mac!(slh_dsa_shake_192f, $($arg),*); true }
            #[cfg(feature = "slh-dsa-shake-256s")]
            "SLH-DSA-SHAKE-256s" => { $mac!(slh_dsa_shake_256s, $($arg),*); true }
            #[cfg(feature = "slh-dsa-shake-256f")]
            "SLH-DSA-SHAKE-256f" => { $mac!(slh_dsa_shake_256f, $($arg),*); true }
            _ => false,
        }
    };
}

fn str_field<'a>(v: &'a Value, key: &str, loc: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{loc} missing {key}"))
}

/// `PH(M)` and its DER OID for an ACVP `hashAlg` name.
/// SHAKE128 is 256 bits and SHAKE256 is 512 bits, matching FIPS 205 Algorithm 23.
fn ph_of(name: &str, message: &[u8], loc: &str) -> (&'static [u8], Vec<u8>) {
    match name {
        "SHA2-224" => (&pre_hash::SHA2_224, Sha224::digest(message).to_vec()),
        "SHA2-256" => (&pre_hash::SHA2_256, Sha256::digest(message).to_vec()),
        "SHA2-384" => (&pre_hash::SHA2_384, Sha384::digest(message).to_vec()),
        "SHA2-512" => (&pre_hash::SHA2_512, Sha512::digest(message).to_vec()),
        "SHA2-512/224" => (&pre_hash::SHA2_512_224, Sha512_224::digest(message).to_vec()),
        "SHA2-512/256" => (&pre_hash::SHA2_512_256, Sha512_256::digest(message).to_vec()),
        "SHA3-224" => (&pre_hash::SHA3_224, Sha3_224::digest(message).to_vec()),
        "SHA3-256" => (&pre_hash::SHA3_256, Sha3_256::digest(message).to_vec()),
        "SHA3-384" => (&pre_hash::SHA3_384, Sha3_384::digest(message).to_vec()),
        "SHA3-512" => (&pre_hash::SHA3_512, Sha3_512::digest(message).to_vec()),
        "SHAKE-128" => {
            let mut ret = vec![0u8; 32];
            let mut hasher = Shake128::default();
            hasher.update(message);
            hasher.finalize_xof().read(&mut ret);
            (&pre_hash::SHAKE_128, ret)
        }
        "SHAKE-256" => {
            let mut ret = vec![0u8; 64];
            let mut hasher = Shake256::default();
            hasher.update(message);
            hasher.finalize_xof().read(&mut ret);
            (&pre_hash::SHAKE_256, ret)
        }
        other => panic!("{loc} unknown hashAlg {other}"),
    }
}

fn keep_siggen(set: &str, iface: &str, pre: &str, det: bool, idx: usize) -> bool {
    if !smoke() {
        return true;
    }
    // All twelve hash algorithms, both hedged and deterministic, on SHA2-128s.
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
    let mut tally = Tally::new(&doc);
    for group in groups(&doc) {
        check_group(group, &["parameterSet", "testType", "tests", "tgId"]);
        let set = str_field(group, "parameterSet", "keyGen group");
        let tg = group["tgId"].as_u64().expect("tgId");
        for test in cases(group) {
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
    tally.finish("keyGen");
}

#[test]
fn nist_siggen() {
    let doc = load("SLH-DSA-sigGen-FIPS205");
    let mut tally = Tally::new(&doc);
    for group in groups(&doc) {
        check_group(group, &[
            "deterministic", "parameterSet", "preHash", "signatureInterface", "testType", "tests", "tgId",
        ]);
        let set = str_field(group, "parameterSet", "sigGen group");
        let tg = group["tgId"].as_u64().expect("tgId");
        let iface = str_field(group, "signatureInterface", "sigGen group");
        let pre = str_field(group, "preHash", "sigGen group");
        let det = group["deterministic"].as_bool().expect("deterministic");
        let internal = is_internal(group);
        let hedged = !det;
        for (idx, test) in cases(group).iter().enumerate() {
            let tc = test["tcId"].as_u64().expect("tcId");
            let loc = loc_of(set, tg, tc);
            if !keep_siggen(set, iface, pre, det, idx) {
                tally.smoke_skipped += 1;
                continue;
            }
            if internal && !cfg!(feature = "acvp-internal") {
                tally.hook_skipped += 1;
                continue;
            }
            let handled = if pre == "preHash" {
                dispatch!(set, sign_hash, test, &loc, hedged)
            } else {
                dispatch!(set, sign_one, test, &loc, internal, hedged)
            };
            if !handled {
                note_unhandled(set, &mut tally);
                continue;
            }
            tally.ran += 1;
        }
    }
    tally.finish("sigGen");
}

#[test]
fn nist_sigver() {
    let doc = load("SLH-DSA-sigVer-FIPS205");
    let mut tally = Tally::new(&doc);
    let mut pick = VerPick {
        reasons_128s: HashSet::new(),
        valid_external: HashSet::new(),
        valid_internal: HashSet::new(),
    };
    for group in groups(&doc) {
        check_group(group, &["parameterSet", "preHash", "signatureInterface", "testType", "tests", "tgId"]);
        let set = str_field(group, "parameterSet", "sigVer group");
        let tg = group["tgId"].as_u64().expect("tgId");
        let iface = str_field(group, "signatureInterface", "sigVer group");
        let pre = str_field(group, "preHash", "sigVer group");
        let internal = is_internal(group);
        for test in cases(group) {
            let tc = test["tcId"].as_u64().expect("tcId");
            let loc = loc_of(set, tg, tc);
            let reason = test["reason"].as_str().unwrap_or("");
            let passed = test["testPassed"].as_bool().unwrap_or(false);
            if !pick.keep(set, iface, pre, reason, passed) {
                tally.smoke_skipped += 1;
                continue;
            }
            if internal && !cfg!(feature = "acvp-internal") {
                tally.hook_skipped += 1;
                continue;
            }
            let handled = if pre == "preHash" {
                dispatch!(set, verify_hash, test, &loc)
            } else {
                dispatch!(set, verify_one, test, &loc, internal)
            };
            if !handled {
                note_unhandled(set, &mut tally);
                continue;
            }
            tally.ran += 1;
        }
    }
    tally.finish("sigVer");
}
