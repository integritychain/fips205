#![no_std]
#![deny(clippy::pedantic)]
#![deny(warnings)]


//#![deny(missing_docs)]
#[allow(dead_code)]
// TODO
//  1. General clean-up
//  2. revisit/clean hash functions
//  3. Doc, of course!

// TKTK crate doc
/// crate doc?
mod algs;
mod hashers;
mod test;
mod traits;
mod types;

// Per eqns 5.1-4 on page 16, LGW=4, W=16 and LEN2=3 are constant across all parameter sets.
const LGW: u32 = 4;
const W: u32 = 16;
const LEN2: u32 = 3;


macro_rules! functionality {
    () => {
        use crate::types::{SlhDsaSig, SlhPrivateKey, SlhPublicKey};
        use generic_array::typenum::{Prod, Sum, U2, U3};
        use rand_core::CryptoRngCore;

        /// blah
        /// # Errors
        pub fn slh_keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(SlhPrivateKey<N>, SlhPublicKey<N>), &'static str> {
            crate::algs::slh_keygen_with_rng::<D, H, HP, K, Sum<Prod<U2, N>, U3>, M, N>(rng, &HASHERS)
        }

        /// blah
        /// # Errors
        pub fn slh_sign_with_rng(
            rng: &mut impl CryptoRngCore, m: &[u8], sk: &SlhPrivateKey<N>, randomize: bool,
        ) -> Result<[u8; SIG_LEN], &'static str> {
            let sig = crate::algs::slh_sign_with_rng::<A, D, H, HP, K, Sum<Prod<U2, N>, U3>, M, N>(
                rng, &HASHERS, &m, &sk, randomize,
            );
            sig.map(|s| s.deserialize())
        }

        /// blah
        #[must_use]
        pub fn slh_verify(m: &[u8], sig_bytes: &[u8; SIG_LEN], pk: &SlhPublicKey<N>) -> bool {
            let sig = SlhDsaSig::<A, D, HP, K, Sum<Prod<U2, N>, U3>, N>::serialize(sig_bytes);
            crate::algs::slh_verify::<A, D, H, HP, K, Sum<Prod<U2, N>, U3>, M, N>(
                &HASHERS, &m, &sig, &pk,
            )
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use rand_chacha::rand_core::SeedableRng;

            #[test]
            fn simple_loop() {
                let mut message = [0u8, 1, 2, 3];
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
                for i in 0..5 {
                    message[3] = i as u8;
                    let (sk, pk) = slh_keygen_with_rng(&mut rng).unwrap();
                    let sig = slh_sign_with_rng(&mut rng, &message, &sk, false).unwrap();
                    let result = slh_verify(&message, &sig, &pk);
                    assert_eq!(result, true, "Signature failed to verify");
                    message[3] = (i + 1) as u8;
                    let result = slh_verify(&message, &sig, &pk);
                    assert_eq!(result, false, "Signature should not have verified");
                }
            }
        }
    };
}

/// TKTK
#[cfg(feature = "slh_dsa_sha2_128s")]
pub mod slh_dsa_sha2_128s {
    use crate::hashers::shake::{f, h, h_msg, prf, prf_msg, t_l, t_len};
    use crate::hashers::Hashers;
    use generic_array::typenum::{U12, U14, U16, U30, U63, U7, U9};

    type N = U16;
    type H = U63;
    type D = U7;
    type HP = U9;
    type A = U12;
    type K = U14;
    type M = U30;
    type LEN = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 7856;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, LEN, M, N> = Hashers::<K, LEN, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len };

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_shake_128s")]
pub mod slh_dsa_shake_128s {
    const N: usize = 16;
    const H: u32 = 63;
    const D: u32 = 7;
    const H_PRIME: u32 = 9;
    const A: u32 = 12;
    const K: u32 = 14;
    const LGW: u32 = 4;
    const M: u32 = 30;
    const PK_LEN: usize = 32;
    const SIG_LEN: usize = 7856;
    const SK_LEN: usize = 0000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_sha2_128f")]
pub mod slh_dsa_sha2_128f {
    const N: usize = 16;
    const H: u32 = 66;
    const D: u32 = 22;
    const H_PRIME: u32 = 3;
    const A: u32 = 6;
    const K: u32 = 33;
    const LGW: u32 = 4;
    const M: u32 = 34;
    const PK_LEN: usize = 32;
    const SIG_LEN: usize = 17088;
    const SK_LEN: usize = 0000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_shake_128f")]
pub mod slh_dsa_shake_128f {
    const N: usize = 16;
    const H: u32 = 66;
    const D: u32 = 22;
    const H_PRIME: u32 = 3;
    const A: u32 = 6;
    const K: u32 = 33;
    const LGW: u32 = 4;
    const M: u32 = 34;
    const PK_LEN: usize = 32;
    const SIG_LEN: usize = 17088;
    const SK_LEN: usize = 0000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_sha2_192s")]
pub mod slh_dsa_sha2_192s {
    const N: usize = 24;
    const H: u32 = 63;
    const D: u32 = 7;
    const H_PRIME: u32 = 9;
    const A: u32 = 14;
    const K: u32 = 17;
    const LGW: u32 = 4;
    const M: u32 = 39;
    const PK_LEN: usize = 48;
    const SIG_LEN: usize = 16224;
    const SK_LEN: usize = 00000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_shake_192s")]
pub mod slh_dsa_shake_192s {
    const N: usize = 24;
    const H: u32 = 63;
    const D: u32 = 7;
    const H_PRIME: u32 = 9;
    const A: u32 = 14;
    const K: u32 = 17;
    const LGW: u32 = 4;
    const M: u32 = 39;
    const PK_LEN: usize = 48;
    const SIG_LEN: usize = 16224;
    const SK_LEN: usize = 00000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_sha2_192f")]
pub mod slh_dsa_sha2_192f {
    const N: usize = 24;
    const H: u32 = 66;
    const D: u32 = 22;
    const H_PRIME: u32 = 3;
    const A: u32 = 8;
    const K: u32 = 33;
    const LGW: u32 = 4;
    const M: u32 = 42;
    const PK_LEN: usize = 48;
    const SIG_LEN: usize = 35664;
    const SK_LEN: usize = 0000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_shake_192f")]
pub mod slh_dsa_shake_192f {
    const N: usize = 24;
    const H: u32 = 66;
    const D: u32 = 22;
    const H_PRIME: u32 = 3;
    const A: u32 = 8;
    const K: u32 = 33;
    const LGW: u32 = 4;
    const M: u32 = 42;
    const PK_LEN: usize = 48;
    const SIG_LEN: usize = 35664;
    const SK_LEN: usize = 0000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_sha2_256s")]
pub mod slh_dsa_sha2_256s {
    const N: usize = 32;
    const H: u32 = 64;
    const D: u32 = 8;
    const H_PRIME: u32 = 8;
    const A: u32 = 14;
    const K: u32 = 22;
    const LGW: u32 = 4;
    const M: u32 = 47;
    const PK_LEN: usize = 64;
    const SIG_LEN: usize = 29792;
    const SK_LEN: usize = 0000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_shake_256s")]
pub mod slh_dsa_shake_256s {
    const N: usize = 32;
    const H: u32 = 64;
    const D: u32 = 8;
    const H_PRIME: u32 = 8;
    const A: u32 = 14;
    const K: u32 = 22;
    const LGW: u32 = 4;
    const M: u32 = 47;
    const PK_LEN: usize = 64;
    const SIG_LEN: usize = 29792;
    const SK_LEN: usize = 0000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_sha2_256f")]
pub mod slh_dsa_sha2_256f {
    const N: usize = 32;
    const H: u32 = 68;
    const D: u32 = 17;
    const H_PRIME: u32 = 4;
    const A: u32 = 9;
    const K: u32 = 35;
    const LGW: u32 = 4;
    const M: u32 = 49;
    const PK_LEN: usize = 64;
    const SIG_LEN: usize = 49856;
    const SK_LEN: usize = 0000;

    functionality!();
}

/// TKTK
#[cfg(feature = "slh_dsa_shake_256f")]
pub mod slh_dsa_shake_256f {
    const N: usize = 32;
    const H: u32 = 68;
    const D: u32 = 17;
    const H_PRIME: u32 = 4;
    const A: u32 = 9;
    const K: u32 = 35;
    const LGW: u32 = 4;
    const M: u32 = 49;
    const PK_LEN: usize = 64;
    const SIG_LEN: usize = 49856;
    const SK_LEN: usize = 0000;

    functionality!();
}
