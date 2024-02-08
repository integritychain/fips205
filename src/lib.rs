#![no_std]
#![deny(clippy::pedantic)]
#![deny(warnings)]
//#![deny(missing_docs)]

/// TKTK crate doc
// TODO
//  1. General clean-up
//  2. SerDes on keys
//  3. Proper traits and non-rng functions
//  4. Adrs as raw bytes
//  5. clippy
//  6. Separate into proper files
//  7. Doc, of course!
mod algs;
mod hashers;
mod test;
mod traits;
mod types;

// Per eqns 5.1-4 on page 16, LGW=4, W=16 and LEN2=3 are constant across all security parameter sets.
const LGW: u32 = 4;
const W: u32 = 16;
const LEN2: u32 = 3;


/// blah
macro_rules! functionality {
    () => {
        use crate::types::{SlhDsaSig, SlhPrivateKey, SlhPublicKey};
        use rand_core::CryptoRngCore;

        /// blah
        /// # Errors
        pub fn slh_keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(SlhPrivateKey<N>, SlhPublicKey<N>), &'static str> {
            crate::algs::slh_keygen_with_rng::<D, H, HP, K, Len, M, N>(rng, &HASHERS)
        }

        /// blah
        /// # Errors
        pub fn slh_sign_with_rng(
            rng: &mut impl CryptoRngCore, m: &[u8], sk: &SlhPrivateKey<N>, randomize: bool,
        ) -> Result<[u8; SIG_LEN], &'static str> {
            let sig = crate::algs::slh_sign_with_rng::<A, D, H, HP, K, Len, M, N>(
                rng, &HASHERS, &m, &sk, randomize,
            );
            sig.map(|s| s.deserialize())
        }

        /// blah
        #[must_use]
        pub fn slh_verify(m: &[u8], sig_bytes: &[u8; SIG_LEN], pk: &SlhPublicKey<N>) -> bool {
            let sig = SlhDsaSig::<A, D, HP, K, Len, N>::serialize(sig_bytes);
            crate::algs::slh_verify::<A, D, H, HP, K, Len, M, N>(&HASHERS, &m, &sig, &pk)
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use rand_chacha::rand_core::SeedableRng;

            #[test]
            fn simple_round_trips() {
                let mut message = [0u8, 1, 2, 3];
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
                for i in 0..5 {
                    message[3] = i as u8;
                    let (sk, pk) = slh_keygen_with_rng(&mut rng).unwrap();
                    let sig = slh_sign_with_rng(&mut rng, &message, &sk, true).unwrap();
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
    use crate::hashers::sha2_cat_1::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U12, U14, U16, U2, U3, U30, U63, U7, U9};

    type N = U16;
    type H = U63;
    type D = U7;
    type HP = U9;
    type A = U12;
    type K = U14;
    type M = U30;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 7856;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_shake_128s")]
pub mod slh_dsa_shake_128s {
    use crate::hashers::shake::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U12, U14, U16, U2, U3, U30, U63, U7, U9};

    type N = U16;
    type H = U63;
    type D = U7;
    type HP = U9;
    type A = U12;
    type K = U14;
    type M = U30;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 7856;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_sha2_128f")]
pub mod slh_dsa_sha2_128f {
    use crate::hashers::sha2_cat_1::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U16, U2, U22, U3, U33, U34, U6, U66};

    type N = U16;
    type H = U66;
    type D = U22;
    type HP = U3;
    type A = U6;
    type K = U33;
    type M = U34;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 17088;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_shake_128f")]
pub mod slh_dsa_shake_128f {
    use crate::hashers::shake::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U16, U2, U22, U3, U33, U34, U6, U66};

    type N = U16;
    type H = U66;
    type D = U22;
    type HP = U3;
    type A = U6;
    type K = U33;
    type M = U34;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 17088;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_sha2_192s")]
pub mod slh_dsa_sha2_192s {
    use crate::hashers::sha2_cat_3_5::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U14, U17, U2, U24, U3, U39, U63, U7, U9};

    type N = U24;
    type H = U63;
    type D = U7;
    type HP = U9;
    type A = U14;
    type K = U17;
    type M = U39;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 16224;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_shake_192s")]
pub mod slh_dsa_shake_192s {
    use crate::hashers::shake::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U14, U17, U2, U24, U3, U39, U63, U7, U9};

    type N = U24;
    type H = U63;
    type D = U7;
    type HP = U9;
    type A = U14;
    type K = U17;
    type M = U39;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 16224;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_sha2_192f")]
pub mod slh_dsa_sha2_192f {
    use crate::hashers::sha2_cat_3_5::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U2, U22, U24, U3, U33, U42, U66, U8};

    type N = U24;
    type H = U66;
    type D = U22;
    type HP = U3;
    type A = U8;
    type K = U33;
    type M = U42;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 35664;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_shake_192f")]
pub mod slh_dsa_shake_192f {
    use crate::hashers::shake::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U2, U22, U24, U3, U33, U42, U66, U8};

    type N = U24;
    type H = U66;
    type D = U22;
    type HP = U3;
    type A = U8;
    type K = U33;
    type M = U42;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 35664;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_sha2_256s")]
pub mod slh_dsa_sha2_256s {
    use crate::hashers::sha2_cat_3_5::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U14, U2, U22, U3, U32, U47, U64, U8};

    type N = U32;
    type H = U64;
    type D = U8;
    type HP = U8;
    type A = U14;
    type K = U22;
    type M = U47;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 29792;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_shake_256s")]
pub mod slh_dsa_shake_256s {
    use crate::hashers::shake::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U14, U2, U22, U3, U32, U47, U64, U8};

    type N = U32;
    type H = U64;
    type D = U8;
    type HP = U8;
    type A = U14;
    type K = U22;
    type M = U47;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 29792;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_sha2_256f")]
pub mod slh_dsa_sha2_256f {
    use crate::hashers::sha2_cat_3_5::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U17, U2, U3, U32, U35, U4, U49, U68, U9};

    type N = U32;
    type H = U68;
    type D = U17;
    type HP = U4;
    type A = U9;
    type K = U35;
    type M = U49;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 49856;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// TKTK
#[cfg(feature = "slh_dsa_shake_256f")]
pub mod slh_dsa_shake_256f {
    use crate::hashers::shake::{f, h, h_msg, prf, prf_msg, t_l};
    use crate::hashers::Hashers;
    use generic_array::typenum::{Prod, Sum, U17, U2, U3, U32, U35, U4, U49, U68, U9};

    type N = U32;
    type H = U68;
    type D = U17;
    type HP = U4;
    type A = U9;
    type K = U35;
    type M = U49;
    type Len = Sum<Prod<U2, N>, U3>;
    //const PK_LEN: usize = 32;
    const SIG_LEN: usize = 49856;
    //const SK_LEN: usize = 0000;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}
