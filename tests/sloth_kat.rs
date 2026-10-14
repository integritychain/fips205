//! SLotH SLH-DSA known-answer files (BSD-3-Clause), regenerated and checked by hash.
//!
//! From <https://github.com/slh-dsa/sloth/tree/c41de2ae113cd90790b0004c58f813c898b62f7a/kat>.
//! The files follow NIST's `PQCgenKAT_sign` for SPHINCS+: an AES-256 CTR DRBG seeded with
//! 0..47 draws each record's 48-byte seed and its 33·(count+1)-byte message; reseeded with that
//! seed, it draws SK.seed || SK.prf || PK.seed for key generation and then `opt_rand` for
//! signing. SLotH targets the FIPS 205 draft, whose `slh_sign_internal` the final standard keeps,
//! so the records are signed with the internal interface (the `acvp-internal` hooks), and each
//! signature must verify. The text of the first 10 records of each parameter set must hash to
//! SLotH's `kat10-sha256.txt` value, or with `FIPS205_NIST_SMOKE=1` (as for the NIST vectors)
//! the first record to `kat1-sha256.txt`. No vector data is stored.

// The `acvp-internal` hooks are deprecated so that nothing outside the tests calls them.
#![allow(deprecated)]
#![cfg(feature = "acvp-internal")]

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use fips205::traits::{KeyGen, SerDes};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt::Write;

fn smoke() -> bool { std::env::var_os("FIPS205_NIST_SMOKE").is_some_and(|v| v == "1") }

// NIST's AES-256 CTR DRBG from the PQC KAT generator (rng.c), without personalization
struct Drbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl Drbg {
    fn new(entropy: &[u8; 48]) -> Self {
        let mut drbg = Drbg { key: [0; 32], v: [0; 16] };
        drbg.update(Some(entropy));
        drbg
    }

    fn block(&mut self) -> [u8; 16] {
        for b in self.v.iter_mut().rev() {
            if *b == 0xff {
                *b = 0;
            } else {
                *b += 1;
                break;
            }
        }
        let mut block = GenericArray::clone_from_slice(&self.v);
        Aes256::new(GenericArray::from_slice(&self.key)).encrypt_block(&mut block);
        block.into()
    }

    fn update(&mut self, provided: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];
        for chunk in temp.chunks_mut(16) {
            chunk.copy_from_slice(&self.block());
        }
        if let Some(provided) = provided {
            temp.iter_mut().zip(provided).for_each(|(t, p)| *t ^= p);
        }
        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..]);
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(16) {
            let block = self.block();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        self.update(None);
    }
}

// Supplies `opt_rand` to the signing hook
struct FixedRng(Vec<u8>);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, out: &mut [u8]) { out.copy_from_slice(&self.0) }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

macro_rules! kat {
    ($name:ident, $pc:ident, $feature:literal, $hash_1:literal, $hash_10:literal) => {
        #[cfg(feature = $feature)]
        #[test]
        fn $name() {
            use fips205::$pc;
            const N: usize = $pc::PK_LEN / 2;
            let (records, expected) = if smoke() { (1, $hash_1) } else { (10, $hash_10) };
            let mut master = Drbg::new(&core::array::from_fn(|i| u8::try_from(i).unwrap()));
            let mut text = String::from("# SPHINCS+\n\n");
            for count in 0..records {
                let mut seed = [0u8; 48];
                master.fill(&mut seed);
                let mlen = 33 * (count + 1);
                let mut msg = vec![0u8; mlen];
                master.fill(&mut msg);

                let mut drbg = Drbg::new(&seed);
                let mut seeds = [0u8; 3 * N];
                drbg.fill(&mut seeds);
                let (pk, sk) = $pc::KG::keygen_from_seed::<N>(
                    &seeds[..N].try_into().unwrap(),
                    &seeds[N..2 * N].try_into().unwrap(),
                    &seeds[2 * N..].try_into().unwrap(),
                );
                let mut opt_rand = vec![0u8; N];
                drbg.fill(&mut opt_rand);
                let sig = sk.sign_internal(&mut FixedRng(opt_rand), &msg, true).unwrap();
                assert!(pk.verify_internal(&msg, &sig), "count {count} verify");

                let sm = [&sig[..], &msg].concat();
                write!(
                    text,
                    "count = {count}\nseed = {}\nmlen = {mlen}\nmsg = {}\npk = {}\nsk = {}\nsmlen = {}\nsm = {}\n\n",
                    hex::encode_upper(seed),
                    hex::encode_upper(&msg),
                    hex::encode_upper(pk.into_bytes()),
                    hex::encode_upper(sk.into_bytes()),
                    sm.len(),
                    hex::encode_upper(&sm),
                )
                .unwrap();
            }
            assert_eq!(hex::encode(Sha256::digest(text.as_bytes())), expected, "{records} records");
        }
    };
}

kat!(
    kat_sha2_128s,
    slh_dsa_sha2_128s,
    "slh-dsa-sha2-128s",
    "a316908dec0998861b647f40213bf37cbfc2b3634b8a0a52e4503dba59bad441",
    "5e501f7c91fa189dff618dda9cca0511140fb85e133bab986c9ef89ed220389e"
);
kat!(
    kat_sha2_128f,
    slh_dsa_sha2_128f,
    "slh-dsa-sha2-128f",
    "d3df72bb154abaef53cc5d0dd5b4fde46a797e90e30805fff7c3e31041ab4c67",
    "c8fcb441611200b19349f2e7fda07c4547bef22f35af6e47a2b8c824e0c2e0be"
);
kat!(
    kat_sha2_192s,
    slh_dsa_sha2_192s,
    "slh-dsa-sha2-192s",
    "601be3028bf69f6c7aecfd709b95c9c778e2420b976967771203e2e824a86321",
    "0d17bdb1d3e7d7f06e88d79f3b65fbeae70694914ec088a3d1c081e65c35a928"
);
kat!(
    kat_sha2_192f,
    slh_dsa_sha2_192f,
    "slh-dsa-sha2-192f",
    "f525b6569082b4335593eab8257364a5754932b2a209fc194c09ffce12bfbb16",
    "73519c7365ac46695ea96dae3283f05a2ddcb1e8f9e0ba800544ba737b746206"
);
kat!(
    kat_sha2_256s,
    slh_dsa_sha2_256s,
    "slh-dsa-sha2-256s",
    "2b23b59d31969dbb91fb5465d26637448c53658631d9c218664e2ad1a2cb69e0",
    "f935d6af17fa16f290421c5112c4c2cee445ba7c332a74fe3d88a7a219c2176b"
);
kat!(
    kat_sha2_256f,
    slh_dsa_sha2_256f,
    "slh-dsa-sha2-256f",
    "1aab628d922a489f6879e29b55e5a474c3b9d4c52b166a52e7504f69bf85057a",
    "e58442029ff40d3f61d5a7d3495fae38500ad4be4db9db1ef4f42a365077b070"
);
kat!(
    kat_shake_128s,
    slh_dsa_shake_128s,
    "slh-dsa-shake-128s",
    "d36999edc06c0daeaae9e6346b4b5a5ea9503387fb343bfe869c5ccd0a90c51c",
    "1930c23fb13b4f95ec11343d9a68d270879bfbb8821c1cfb59b37cd0b5e4665e"
);
kat!(
    kat_shake_128f,
    slh_dsa_shake_128f,
    "slh-dsa-shake-128f",
    "6452ae18c387c7816d1396b0919c824479d0ab02f91010f59d26cd405fe309b4",
    "056ee235f9a8ff3fb3f3799807d82690ffe3ff5681f0c6e3809ddca4fb539b29"
);
kat!(
    kat_shake_192s,
    slh_dsa_shake_192s,
    "slh-dsa-shake-192s",
    "84644ef3f842f5939f48179bcbc1f8c0e494f5a76585c71a176547e6ef297517",
    "7d35e89f91116f0869d7a7591df026c4033f8ca3e33d795f03b25905277175cd"
);
kat!(
    kat_shake_192f,
    slh_dsa_shake_192f,
    "slh-dsa-shake-192f",
    "7cf1ae6803f24d2fabcc2f98e77ab703fc223b6d5ddd5091658d03c13c3045b2",
    "d83825fb99bc22a3eb4ae388a9e88716b5cae0622682a210bd11f7b8ffbd47ee"
);
kat!(
    kat_shake_256s,
    slh_dsa_shake_256s,
    "slh-dsa-shake-256s",
    "b399077b5c53daffd830df98dd3953b9db1903a151bc679adff314a93cf808d0",
    "7c8f16c7b9645df58518b1c0aa7a26f7a2e1b9ee860819f25305cf97aecce1f3"
);
kat!(
    kat_shake_256f,
    slh_dsa_shake_256f,
    "slh-dsa-shake-256f",
    "049ff342c967ee43f586052249ba3313297e6630c1095d2af869853a717f0acd",
    "be37b5222c98b3a1f0d2d3d69bc32205ed17e93c6a4da684c76ee1ca29ec28ef"
);
