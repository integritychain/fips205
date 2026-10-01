//! Python known-answer inputs, exercised on the public sign and verify path.
//! The old expected signatures were for `_test_only_raw_sign` (no domain
//! separator). This checks keygen, hedged `try_sign_with_rng` with an empty
//! context, and `verify` on those same seeds and message.

use fips205::traits::{KeyGen, Signer, Verifier};
use hex::decode;
use rand_core::{CryptoRng, RngCore};

struct TestRng {
    data: Vec<Vec<u8>>,
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let x = self.data.pop().expect("TestRng problem");
        out.copy_from_slice(&x);
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

const MSG: &str = "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8";

macro_rules! py_case {
    ($name:ident, $feat:literal, $m:ident, $sk:literal, $prf:literal, $pk:literal, $rnd:literal) => {
        #[cfg(feature = $feat)]
        #[test]
        fn $name() {
            let msg = decode(MSG).unwrap();
            let mut rnd = TestRng { data: Vec::new() };
            // Pop order is sk_seed, sk_prf, pk_seed, then opt_rand for the signature.
            rnd.data.push(decode($rnd).unwrap());
            rnd.data.push(decode($pk).unwrap());
            rnd.data.push(decode($prf).unwrap());
            rnd.data.push(decode($sk).unwrap());
            let (pk, sk) = <fips205::$m::KG as KeyGen>::try_keygen_with_rng(&mut rnd).unwrap();
            let sig = sk.try_sign_with_rng(&mut rnd, &msg, &[], true).unwrap();
            assert!(pk.verify(&msg, &sig, &[]), stringify!($name));
        }
    };
}

py_case!(
    vector_slh_dsa_sha2_128s,
    "slh_dsa_sha2_128s",
    slh_dsa_sha2_128s,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD",
    "2FD81A25CCB148032DCD739936737F2D",
    "B505D7CFAD1B497499323C8686325E47",
    "33B3C07507E4201748494D832B6EE2A6"
);
py_case!(
    vector_slh_dsa_sha2_128f,
    "slh_dsa_sha2_128f",
    slh_dsa_sha2_128f,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD",
    "2FD81A25CCB148032DCD739936737F2D",
    "B505D7CFAD1B497499323C8686325E47",
    "33B3C07507E4201748494D832B6EE2A6"
);
py_case!(
    vector_slh_dsa_shake_128s,
    "slh_dsa_shake_128s",
    slh_dsa_shake_128s,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD",
    "2FD81A25CCB148032DCD739936737F2D",
    "B505D7CFAD1B497499323C8686325E47",
    "33B3C07507E4201748494D832B6EE2A6"
);
py_case!(
    vector_slh_dsa_shake_128f,
    "slh_dsa_shake_128f",
    slh_dsa_shake_128f,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD",
    "2FD81A25CCB148032DCD739936737F2D",
    "B505D7CFAD1B497499323C8686325E47",
    "33B3C07507E4201748494D832B6EE2A6"
);
py_case!(
    vector_slh_dsa_sha2_192s,
    "slh_dsa_sha2_192s",
    slh_dsa_sha2_192s,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB14803",
    "2DCD739936737F2DB505D7CFAD1B497499323C8686325E47",
    "92F267AAFA3F87CA60D01CB54F29202A3E784CCB7EBCDCFD",
    "8BF0F459F0FB3EA8D32764C259AE631178976BAF3683D333"
);
py_case!(
    vector_slh_dsa_sha2_192f,
    "slh_dsa_sha2_192f",
    slh_dsa_sha2_192f,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB14803",
    "2DCD739936737F2DB505D7CFAD1B497499323C8686325E47",
    "92F267AAFA3F87CA60D01CB54F29202A3E784CCB7EBCDCFD",
    "8BF0F459F0FB3EA8D32764C259AE631178976BAF3683D333"
);
py_case!(
    vector_slh_dsa_shake_192s,
    "slh_dsa_shake_192s",
    slh_dsa_shake_192s,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB14803",
    "2DCD739936737F2DB505D7CFAD1B497499323C8686325E47",
    "92F267AAFA3F87CA60D01CB54F29202A3E784CCB7EBCDCFD",
    "8BF0F459F0FB3EA8D32764C259AE631178976BAF3683D333"
);
py_case!(
    vector_slh_dsa_shake_192f,
    "slh_dsa_shake_192f",
    slh_dsa_shake_192f,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB14803",
    "2DCD739936737F2DB505D7CFAD1B497499323C8686325E47",
    "92F267AAFA3F87CA60D01CB54F29202A3E784CCB7EBCDCFD",
    "8BF0F459F0FB3EA8D32764C259AE631178976BAF3683D333"
);
py_case!(
    vector_slh_dsa_sha2_256s,
    "slh_dsa_sha2_256s",
    slh_dsa_sha2_256s,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D",
    "B505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A",
    "3E784CCB7EBCDCFD45542B7F6AF778742E0F4479175084AA488B3B74340678AA",
    "EE716762C15E3B72AA7650A63B9A510040B03C0FE70475C0463BBC45A0BA5B79"
);
py_case!(
    vector_slh_dsa_sha2_256f,
    "slh_dsa_sha2_256f",
    slh_dsa_sha2_256f,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D",
    "B505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A",
    "3E784CCB7EBCDCFD45542B7F6AF778742E0F4479175084AA488B3B74340678AA",
    "EE716762C15E3B72AA7650A63B9A510040B03C0FE70475C0463BBC45A0BA5B79"
);
py_case!(
    vector_slh_dsa_shake_256s,
    "slh_dsa_shake_256s",
    slh_dsa_shake_256s,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D",
    "B505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A",
    "3E784CCB7EBCDCFD45542B7F6AF778742E0F4479175084AA488B3B74340678AA",
    "EE716762C15E3B72AA7650A63B9A510040B03C0FE70475C0463BBC45A0BA5B79"
);
py_case!(
    vector_slh_dsa_shake_256f,
    "slh_dsa_shake_256f",
    slh_dsa_shake_256f,
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D",
    "B505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A",
    "3E784CCB7EBCDCFD45542B7F6AF778742E0F4479175084AA488B3B74340678AA",
    "EE716762C15E3B72AA7650A63B9A510040B03C0FE70475C0463BBC45A0BA5B79"
);
