#![no_std]
#![deny(clippy::pedantic)]
#![deny(warnings)]
//#![deny(missing_docs)]

/// TKTK crate doc
// TODO
//  1. General clean-up
//  7. Doc, of course!
mod fors;
mod hashers;
mod helpers;
mod hypertree;
mod slh;
mod test;
mod traits;
mod types;
mod wots;
mod xmss;


// Per eqns 5.1-4 on page 16, LGW=4, W=16 and LEN2=3 are constant across all security parameter sets.
const LGW: u32 = 4;
const W: u32 = 16;
const LEN2: u32 = 3;


/// blah
macro_rules! functionality {
    () => {
        use crate::traits::{KeyGen, SerDes, Signer, Verifier};
        use crate::types::{SlhDsaSig, SlhPrivateKey, SlhPublicKey};
        use rand_core::CryptoRngCore;
        use zeroize::{Zeroize, ZeroizeOnDrop};


        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct PublicKey(SlhPublicKey<N>);

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct PrivateKey(SlhPrivateKey<N>);

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct KG(); // Arguable how useful an empty struct+trait is...


        /// blah
        /// # Errors
        impl KeyGen for KG {
            type PrivateKey = PrivateKey;
            type PublicKey = PublicKey;

            fn try_keygen_with_rng_vt(
                rng: &mut impl CryptoRngCore,
            ) -> Result<(PublicKey, PrivateKey), &'static str> {
                let res = crate::slh::slh_keygen_with_rng::<D, H, HP, K, Len, M, N>(rng, &HASHERS);
                res.map(|(sk, pk)| (PublicKey(pk), PrivateKey(sk)))
            }
        }


        /// blah
        /// # Errors
        #[cfg(feature = "default-rng")]
        pub fn try_keygen_vt() -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::try_keygen_vt()
        }


        impl Signer for PrivateKey {
            type Signature = [u8; SIG_LEN];

            /// blah
            /// # Errors
            fn try_sign_with_rng_ct(
                &self, rng: &mut impl CryptoRngCore, m: &[u8], randomize: bool,
            ) -> Result<[u8; SIG_LEN], &'static str> {
                let sig = crate::slh::slh_sign_with_rng::<A, D, H, HP, K, Len, M, N>(
                    rng, &HASHERS, &m, &self.0, randomize,
                );
                sig.map(|s| s.deserialize())
            }
        }


        impl Verifier for PublicKey {
            type Signature = [u8; SIG_LEN];

            /// blah
            fn try_verify_vt(
                &self, m: &[u8], sig_bytes: &[u8; SIG_LEN],
            ) -> Result<bool, &'static str> {
                let sig = SlhDsaSig::<A, D, HP, K, Len, N>::serialize(sig_bytes);
                let res = crate::slh::slh_verify::<A, D, H, HP, K, Len, M, N>(
                    &HASHERS, &m, &sig, &self.0,
                );
                Ok(res)
            }
        }


        impl SerDes for PublicKey {
            type ByteArray = [u8; PK_LEN];

            fn into_bytes(self) -> Self::ByteArray {
                let mut out = [0u8; PK_LEN];
                out[0..(PK_LEN / 2)].copy_from_slice(&self.0.pk_seed);
                out[(PK_LEN / 2)..].copy_from_slice(&self.0.pk_root);
                out
            }

            fn try_from_bytes(bytes: &Self::ByteArray) -> Result<Self, &'static str> {
                // Result: opportunity for validation
                let mut pk = SlhPublicKey::default();
                pk.pk_seed.copy_from_slice(&bytes[..(PK_LEN / 2)]);
                pk.pk_root.copy_from_slice(&bytes[(PK_LEN / 2)..]);
                Ok(PublicKey(pk))
            }
        }


        impl SerDes for PrivateKey {
            type ByteArray = [u8; SK_LEN];

            fn into_bytes(self) -> Self::ByteArray {
                let mut bytes = [0u8; SK_LEN];
                bytes[0..(SK_LEN / 4)].copy_from_slice(&self.0.sk_seed);
                bytes[(SK_LEN / 4)..(SK_LEN / 2)].copy_from_slice(&self.0.sk_prf);
                bytes[(SK_LEN / 2)..(3 * SK_LEN / 4)].copy_from_slice(&self.0.pk_seed);
                bytes[(3 * SK_LEN / 4)..].copy_from_slice(&self.0.pk_root);
                bytes
            }

            fn try_from_bytes(bytes: &Self::ByteArray) -> Result<Self, &'static str> {
                // Result: opportunity for validation
                let mut sk = SlhPrivateKey::default();
                sk.sk_seed.copy_from_slice(&bytes[0..(SK_LEN / 4)]);
                sk.sk_prf
                    .copy_from_slice(&bytes[(SK_LEN / 4)..(SK_LEN / 2)]);
                sk.pk_seed
                    .copy_from_slice(&bytes[(SK_LEN / 2)..(3 * SK_LEN / 4)]);
                sk.pk_root.copy_from_slice(&bytes[(3 * SK_LEN / 4)..]);
                Ok(PrivateKey(sk))
            }
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
                    let (pk1, sk1) = KG::try_keygen_with_rng_vt(&mut rng).unwrap();
                    let pk1_bytes = pk1.into_bytes();
                    let pk2 = PublicKey::try_from_bytes(&pk1_bytes).unwrap();
                    let sk1_bytes = sk1.into_bytes();
                    let sk2 = PrivateKey::try_from_bytes(&sk1_bytes).unwrap();
                    let sig = sk2.try_sign_with_rng_ct(&mut rng, &message, true).unwrap();
                    let result = pk2.try_verify_vt(&message, &sig).unwrap();
                    assert_eq!(result, true, "Signature failed to verify");
                    message[3] = (i + 1) as u8;
                    let result = pk2.try_verify_vt(&message, &sig).unwrap();
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

    pub const PK_LEN: usize = 32;
    pub const SIG_LEN: usize = 7856;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 32;
    pub const SIG_LEN: usize = 7856;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 32;
    pub const SIG_LEN: usize = 17088;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 32;
    pub const SIG_LEN: usize = 17088;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 48;
    pub const SIG_LEN: usize = 16224;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 48;
    pub const SIG_LEN: usize = 16224;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 48;
    pub const SIG_LEN: usize = 35664;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 48;
    pub const SIG_LEN: usize = 35664;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 64;
    pub const SIG_LEN: usize = 29792;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 64;
    pub const SIG_LEN: usize = 29792;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 64;
    pub const SIG_LEN: usize = 49856;
    pub const SK_LEN: usize = PK_LEN * 2;
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

    pub const PK_LEN: usize = 64;
    pub const SIG_LEN: usize = 49856;
    pub const SK_LEN: usize = PK_LEN * 2;
    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}
