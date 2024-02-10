#![no_std]
#![deny(clippy::pedantic)]
#![deny(warnings)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]


/// Implements FIPS 205 draft Stateless Hash-Based Digital Signature Standard.
/// See <https://csrc.nist.gov/pubs/fips/205/ipd>

/// All functionality is covered by traits, such that consumers can utilize trait objects as desired.
pub mod traits;


mod fors;
mod hashers;
mod helpers;
mod hypertree;
mod slh;
mod types;
mod wots;
mod xmss;


// Per eqns 5.1-4 on page 16, LGW=4, W=16 and LEN2=3 are constant across all security parameter sets.
const LGW: u32 = 4;
const W: u32 = 16;
const LEN2: u32 = 3;


// This common functionality is injected into each parameter set module
macro_rules! functionality {
    () => {
        use crate::traits::{KeyGen, SerDes, Signer, Verifier};
        use crate::types::{SlhDsaSig, SlhPrivateKey, SlhPublicKey};
        use rand_core::CryptoRngCore;
        use zeroize::{Zeroize, ZeroizeOnDrop};


        // ----- 'EXTERNAL' DATA TYPES -----

        /// Correctly sized private key specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::Signer`] and [`crate::traits::SerDes`] traits.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct PrivateKey(SlhPrivateKey<N>);

        /// Correctly sized public key specific to the target security parameter set. <br>
        /// Implements the [`crate::traits::Verifier`] and [`crate::traits::SerDes`] traits.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct PublicKey(SlhPublicKey<N>);

        /// Empty struct to enable `KeyGen` trait objects across security parameter sets. <br>
        /// Implements the [`crate::traits::KeyGen`] trait.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct KG(); // Arguable how useful an empty struct+trait is...


        // ----- PRIMARY FUNCTIONS ---

        /// Generates a public and private key pair specific to this security parameter set. <br>
        /// This function utilizes the OS default random number generator, and makes no (constant)
        /// timing assurances.
        /// # Errors
        /// Returns an error when the random number generator fails; propagates internal errors.
        /// # Examples
        /// ```rust
        /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
        /// use fips205::traits::{SerDes, Signer, Verifier};
        /// # use std::error::Error;
        /// #
        /// # fn main() -> Result<(), Box<dyn Error>> {
        ///
        /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
        ///
        /// // Generate public/private key pair and signature
        /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen_vt()?;  // Generate both public and secret keys
        /// let sig_bytes = sk.try_sign_ct(&msg_bytes, true)?;  // Use the secret key to generate a msg signature
        ///
        /// // Serialize the public key, and send with message and signature bytes
        /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
        /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
        ///
        /// // Deserialize the public key, then use it to verify the msg signature
        /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
        /// let v = pk2.try_verify_vt(&msg_recv, &sig_recv)?;
        /// assert!(v);
        /// # Ok(())
        /// # }
        /// ```
        #[cfg(feature = "default-rng")]
        pub fn try_keygen_vt() -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::try_keygen_vt()
        }


        /// Generates a public and private key pair specific to this security parameter set. <br>
        /// This function utilizes a supplied random number generator, and makes no (constant)
        /// timing assurances.
        /// # Errors
        /// Returns an error when the random number generator fails; propagates internal errors.
        /// # Examples
        /// ```rust
        /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
        /// use fips205::traits::{SerDes, Signer, Verifier};
        /// use rand_chacha::rand_core::SeedableRng;
        /// # use std::error::Error;
        /// #
        /// # fn main() -> Result<(), Box<dyn Error>> {
        ///
        /// let message = [0u8, 1, 2, 3, 4, 5, 6, 7];
        /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
        ///
        /// // Generate key pair and signature
        /// let (pk, sk) = slh_dsa_shake_128s::try_keygen_with_rng_vt(&mut rng)?;  // Generate both public and secret keys
        /// let sig = sk.try_sign_ct(&message, true)?;  // Use the secret key to generate a message signature        ///
        /// let v = pk.try_verify_vt(&message, &sig)?;
        /// assert!(v);
        /// # Ok(())}
        /// ```
        pub fn try_keygen_with_rng_vt(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::try_keygen_with_rng_vt(rng)
        }


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


        impl Signer for PrivateKey {
            type Signature = [u8; SIG_LEN];

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


        // ----- SERIALIZATION AND DESERIALIZATION ---

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

            // Test keygen, sign, serDes everything, verify true/false
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


/// Functionality for the **SLH-DSA-SHA2-128s** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHA2-128s parameter set is claimed to be in security strength category 1.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_sha2_128s::try_keygen_vt`] function below
/// to generate both [`slh_dsa_sha2_128s::PublicKey`] and [`slh_dsa_sha2_128s::PrivateKey`] structs. The resulting
/// [`slh_dsa_sha2_128s::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_sha2_128s::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 32;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 7856;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHAKE-128s** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHAKE-128s parameter set is claimed to be in security strength category 1.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_shake_128s::try_keygen_vt`] function below
/// to generate both [`slh_dsa_shake_128s::PublicKey`] and [`slh_dsa_shake_128s::PrivateKey`] structs. The resulting
/// [`slh_dsa_shake_128s::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_shake_128s::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 32;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 7856;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHA2-128f** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHA2-128f parameter set is claimed to be in security strength category 1.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_sha2_128f::try_keygen_vt`] function below
/// to generate both [`slh_dsa_sha2_128f::PublicKey`] and [`slh_dsa_sha2_128f::PrivateKey`] structs. The resulting
/// [`slh_dsa_sha2_128f::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_sha2_128f::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 32;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 17088;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHAKE-128f** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHAKE-128f parameter set is claimed to be in security strength category 1.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_shake_128f::try_keygen_vt`] function below
/// to generate both [`slh_dsa_shake_128f::PublicKey`] and [`slh_dsa_shake_128f::PrivateKey`] structs. The resulting
/// [`slh_dsa_shake_128f::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_shake_128f::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 32;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 17088;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHA2-192s** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHA2-192s parameter set is claimed to be in security strength category 3.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_sha2_192s::try_keygen_vt`] function below
/// to generate both [`slh_dsa_sha2_192s::PublicKey`] and [`slh_dsa_sha2_192s::PrivateKey`] structs. The resulting
/// [`slh_dsa_sha2_192s::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_sha2_192s::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 48;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 16224;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHAKE-192s** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHAKE-192s parameter set is claimed to be in security strength category 3.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_shake_192s::try_keygen_vt`] function below
/// to generate both [`slh_dsa_shake_192s::PublicKey`] and [`slh_dsa_shake_192s::PrivateKey`] structs. The resulting
/// [`slh_dsa_shake_192s::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_shake_192s::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 48;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 16224;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHA2-192f** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHA2-192f parameter set is claimed to be in security strength category 3.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_sha2_192f::try_keygen_vt`] function below
/// to generate both [`slh_dsa_sha2_192f::PublicKey`] and [`slh_dsa_sha2_192f::PrivateKey`] structs. The resulting
/// [`slh_dsa_sha2_192f::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_sha2_192f::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 48;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 35664;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHAKE-192f** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHAKE-192f parameter set is claimed to be in security strength category 3.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_shake_192f::try_keygen_vt`] function below
/// to generate both [`slh_dsa_shake_192f::PublicKey`] and [`slh_dsa_shake_192f::PrivateKey`] structs. The resulting
/// [`slh_dsa_shake_192f::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_shake_192f::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 48;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 35664;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHA2-256s** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHA2-256s parameter set is claimed to be in security strength category 5.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_sha2_256s::try_keygen_vt`] function below
/// to generate both [`slh_dsa_sha2_256s::PublicKey`] and [`slh_dsa_sha2_256s::PrivateKey`] structs. The resulting
/// [`slh_dsa_sha2_256s::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_sha2_256s::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 64;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 29792;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHAKE-256s** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHAKE_256s parameter set is claimed to be in security strength category 5.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_shake_256s::try_keygen_vt`] function below
/// to generate both [`slh_dsa_shake_256s::PublicKey`] and [`slh_dsa_shake_256s::PrivateKey`] structs. The resulting
/// [`slh_dsa_shake_256s::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_shake_256s::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 64;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 29792;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHA2-256f** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHA2-256f parameter set is claimed to be in security strength category 5.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_sha2_256f::try_keygen_vt`] function below
/// to generate both [`slh_dsa_sha2_256f::PublicKey`] and [`slh_dsa_sha2_256f::PrivateKey`] structs. The resulting
/// [`slh_dsa_sha2_256f::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_sha2_256f::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 64;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 49856;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}


/// Functionality for the **SLH-DSA-SHAKE-256f** security parameter set per FIPS 205 section 10. This includes specific
/// sizes for the public key, secret key, and signature along with a number of internal constants. The
/// SLH-DSA-SHAKE-256f parameter set is claimed to be in security strength category 5.
///
/// **1)** The basic usage is for an originator to start with the [`slh_dsa_shake_256f::try_keygen_vt`] function below
/// to generate both [`slh_dsa_shake_256f::PublicKey`] and [`slh_dsa_shake_256f::PrivateKey`] structs. The resulting
/// [`slh_dsa_shake_256f::PrivateKey`] struct implements the [`traits::Signer`] trait which supplies several functions
/// to sign byte-array messages, such as [`traits::Signer::try_sign_ct()`], resulting in a Signature byte-array.
///
/// **2)** Both the `PrivateKey` and `PublicKey` structs implement the [`traits::SerDes`] trait. The originator
/// utilizes the [`traits::SerDes::into_bytes()`] functions to serialize the `PublicKey` struct into a byte-array for
/// distribution. The remote party utilizes the [`traits::SerDes::try_from_bytes()`] function to deserialize the
/// `PublicKey` byte-array into its struct.
///
/// **3)** Finally, the remote party uses the [`traits::Verifier::try_verify_vt()`] function implemented on the
/// [`slh_dsa_shake_256f::PublicKey`] struct to verify the message byte-array with the Signature byte-array..
///
/// See the top-level [crate] documentation for example code that implements the above flow.
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

    /// Length of public key
    pub const PK_LEN: usize = 64;

    /// Length of signature byte-array
    pub const SIG_LEN: usize = 49856;

    /// Length of private/secret key
    pub const SK_LEN: usize = PK_LEN * 2;

    static HASHERS: Hashers<K, Len, M, N> =
        Hashers::<K, Len, M, N> { h_msg, prf, prf_msg, f, h, t_l, t_len: t_l };

    functionality!();
}
