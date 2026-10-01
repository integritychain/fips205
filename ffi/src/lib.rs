//! C ABI for the four 128-bit SLH-DSA parameter sets.
//!
//! `slh_dsa_keygen_seed` is `sk_seed || sk_prf || pk_seed` (3 × 16 bytes).
//! `slh_dsa_sign_seed` is the 16-byte hedged `opt_rand`. A null keygen or sign
//! seed means "draw from the OS RNG". Deterministic signing is `hedged == 0`,
//! which uses `PK.seed` and does not read the sign seed. An all-zero sign seed
//! with `hedged != 0` is a hedged signature whose randomness is zeros, not the
//! deterministic variant.

use pastey::paste;
use rand_core::{CryptoRng, OsRng, RngCore};

const SIGN_N: usize = 16;
const KEYGEN_SEED_LEN: usize = SIGN_N * 3;

fn rng_fail(code: u32) -> rand_core::Error {
    // `Error::new` needs rand_core's `std` feature. The library stays on
    // `getrandom` only, so report a nonzero code instead.
    rand_core::Error::from(core::num::NonZeroU32::new(code).expect("nonzero"))
}

mod ret {
    pub const OK: u8 = 0;
    pub const NULL_PTR_ERROR: u8 = 1;
    #[allow(dead_code)]
    pub const SERIALIZATION_ERROR: u8 = 2;
    pub const DESERIALIZATION_ERROR: u8 = 3;
    pub const KEYGEN_ERROR: u8 = 4;
    pub const SIGN_ERROR: u8 = 5;
    #[allow(dead_code)]
    pub const VERIFICATION_ERROR: u8 = 6;
    pub const VERIFICATION_FAILURE: u8 = 7;
}

#[repr(C)]
pub struct slh_dsa_keygen_seed {
    data: [u8; KEYGEN_SEED_LEN],
}

#[repr(C)]
pub struct slh_dsa_sign_seed {
    data: [u8; SIGN_N],
}

struct NopRng;

impl RngCore for NopRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, _out: &mut [u8]) {
        unimplemented!()
    }

    fn try_fill_bytes(&mut self, _out: &mut [u8]) -> Result<(), rand_core::Error> {
        Err(rng_fail(1))
    }
}

impl CryptoRng for NopRng {}

struct FixedRng<'a> {
    data: &'a [u8],
}

impl RngCore for FixedRng<'_> {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.try_fill_bytes(out).expect("sign seed length");
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        if out.len() != self.data.len() {
            return Err(rng_fail(2));
        }
        out.copy_from_slice(self.data);
        Ok(())
    }
}

impl CryptoRng for FixedRng<'_> {}

#[no_mangle]
pub extern "C" fn slh_dsa_populate_seed(seed_out: Option<&mut slh_dsa_keygen_seed>) -> u8 {
    let Some(seed_out) = seed_out else {
        return ret::NULL_PTR_ERROR;
    };
    OsRng.fill_bytes(&mut seed_out.data);
    ret::OK
}

macro_rules! slice_from_c_buf {
    ($ptr:ident, $len:ident) => {
        if $len == 0 {
            &[]
        } else if $ptr.is_null() {
            return ret::NULL_PTR_ERROR;
        } else {
            unsafe { std::slice::from_raw_parts($ptr, $len) }
        }
    };
}

macro_rules! parameter_set {
    ($pc:ident) => {
        mod $pc {
            use crate::ret;
            use crate::slh_dsa_keygen_seed;
            use crate::slh_dsa_sign_seed;
            use crate::FixedRng;
            use crate::NopRng;
            use crate::KEYGEN_SEED_LEN;
            use crate::SIGN_N;

            const _: () = assert!(fips205::$pc::N == SIGN_N);

            #[repr(C)]
            pub struct c_private_key {
                data: [u8; fips205::$pc::SK_LEN],
            }
            #[repr(C)]
            pub struct c_public_key {
                data: [u8; fips205::$pc::PK_LEN],
            }
            #[repr(C)]
            pub struct c_signature {
                data: [u8; fips205::$pc::SIG_LEN],
            }

            pub fn keygen(
                seed: Option<&slh_dsa_keygen_seed>,
                public_out: Option<&mut c_public_key>,
                private_out: Option<&mut c_private_key>,
            ) -> u8 {
                use fips205::traits::{KeyGen, SerDes};

                let (Some(public_out), Some(private_out)) = (public_out, private_out) else {
                    return ret::NULL_PTR_ERROR;
                };

                let (pubkey, privkey) = match seed {
                    None => {
                        let Ok((pubkey, privkey)) = fips205::$pc::KG::try_keygen() else {
                            return ret::KEYGEN_ERROR;
                        };
                        (pubkey, privkey)
                    }
                    Some(seed) => {
                        let mut sk_seed = [0u8; SIGN_N];
                        let mut sk_prf = [0u8; SIGN_N];
                        let mut pk_seed = [0u8; SIGN_N];
                        sk_seed.copy_from_slice(&seed.data[0..SIGN_N]);
                        sk_prf.copy_from_slice(&seed.data[SIGN_N..SIGN_N * 2]);
                        pk_seed.copy_from_slice(&seed.data[SIGN_N * 2..KEYGEN_SEED_LEN]);
                        fips205::$pc::KG::keygen_with_seeds(&sk_seed, &sk_prf, &pk_seed)
                    }
                };

                public_out.data = pubkey.into_bytes();
                private_out.data = privkey.into_bytes();
                ret::OK
            }

            pub fn get_public_key(
                private: Option<&c_private_key>,
                public_out: Option<&mut c_public_key>,
            ) -> u8 {
                use fips205::traits::{SerDes, Signer};

                let (Some(public_out), Some(private)) = (public_out, private) else {
                    return ret::NULL_PTR_ERROR;
                };
                let Ok(privkey) = fips205::$pc::PrivateKey::try_from_bytes(&private.data) else {
                    return ret::DESERIALIZATION_ERROR;
                };
                let pubkey = privkey.get_public_key();

                public_out.data = pubkey.into_bytes();
                ret::OK
            }

            pub fn sign(
                private: Option<&c_private_key>,
                message: *const u8,
                message_size: usize,
                context: *const u8,
                context_size: usize,
                signature_out: Option<&mut c_signature>,
                seed: Option<&slh_dsa_sign_seed>,
                hedged: u8,
            ) -> u8 {
                use fips205::traits::{SerDes, Signer};

                let (Some(private), Some(signature_out)) = (private, signature_out) else {
                    return ret::NULL_PTR_ERROR;
                };

                let msg = slice_from_c_buf!(message, message_size);
                let ctx = slice_from_c_buf!(context, context_size);

                let Ok(privkey) = fips205::$pc::PrivateKey::try_from_bytes(&private.data) else {
                    return ret::DESERIALIZATION_ERROR;
                };
                let hedged = hedged != 0;
                let ans = match (seed, hedged) {
                    (_, false) => privkey.try_sign_with_rng(&mut NopRng, msg, ctx, false),
                    (None, true) => privkey.try_sign(msg, ctx, true),
                    (Some(seed), true) => {
                        let mut rng = FixedRng { data: &seed.data };
                        privkey.try_sign_with_rng(&mut rng, msg, ctx, true)
                    }
                };
                let Ok(sig) = ans else {
                    return ret::SIGN_ERROR;
                };

                signature_out.data = sig;
                ret::OK
            }

            pub fn hash_sign(
                private: Option<&c_private_key>,
                hash: *const u8,
                hash_size: usize,
                context: *const u8,
                context_size: usize,
                hash_oid: *const u8,
                hash_oid_size: usize,
                signature_out: Option<&mut c_signature>,
                seed: Option<&slh_dsa_sign_seed>,
                hedged: u8,
            ) -> u8 {
                use fips205::traits::{SerDes, Signer};

                let (Some(private), Some(signature_out)) = (private, signature_out) else {
                    return ret::NULL_PTR_ERROR;
                };

                let digest = slice_from_c_buf!(hash, hash_size);
                let ctx = slice_from_c_buf!(context, context_size);
                let hoid = slice_from_c_buf!(hash_oid, hash_oid_size);

                let Ok(privkey) = fips205::$pc::PrivateKey::try_from_bytes(&private.data) else {
                    return ret::DESERIALIZATION_ERROR;
                };
                let hedged = hedged != 0;
                let ans = match (seed, hedged) {
                    (_, false) => privkey.try_hash_sign_with_rng(&mut NopRng, digest, ctx, hoid, false),
                    (None, true) => privkey.try_hash_sign(digest, ctx, hoid, true),
                    (Some(seed), true) => {
                        let mut rng = FixedRng { data: &seed.data };
                        privkey.try_hash_sign_with_rng(&mut rng, digest, ctx, hoid, true)
                    }
                };
                let Ok(sig) = ans else {
                    return ret::SIGN_ERROR;
                };

                signature_out.data = sig;
                ret::OK
            }

            pub fn verify(
                public: Option<&c_public_key>,
                signature: Option<&c_signature>,
                message: *const u8,
                message_size: usize,
                context: *const u8,
                context_size: usize,
            ) -> u8 {
                use fips205::traits::{SerDes, Verifier};

                let (Some(public), Some(signature)) = (public, signature) else {
                    return ret::NULL_PTR_ERROR;
                };

                let msg = slice_from_c_buf!(message, message_size);
                let ctx = slice_from_c_buf!(context, context_size);

                let Ok(pubkey) = fips205::$pc::PublicKey::try_from_bytes(&public.data) else {
                    return ret::DESERIALIZATION_ERROR;
                };

                if pubkey.verify(msg, &signature.data, ctx) {
                    ret::OK
                } else {
                    ret::VERIFICATION_FAILURE
                }
            }

            pub fn hash_verify(
                public: Option<&c_public_key>,
                signature: Option<&c_signature>,
                hash: *const u8,
                hash_size: usize,
                context: *const u8,
                context_size: usize,
                hash_oid: *const u8,
                hash_oid_size: usize,
            ) -> u8 {
                use fips205::traits::{SerDes, Verifier};

                let (Some(public), Some(signature)) = (public, signature) else {
                    return ret::NULL_PTR_ERROR;
                };

                let digest = slice_from_c_buf!(hash, hash_size);
                let ctx = slice_from_c_buf!(context, context_size);
                let hoid = slice_from_c_buf!(hash_oid, hash_oid_size);

                let Ok(pubkey) = fips205::$pc::PublicKey::try_from_bytes(&public.data) else {
                    return ret::DESERIALIZATION_ERROR;
                };

                if pubkey.hash_verify(digest, &signature.data, ctx, hoid) {
                    ret::OK
                } else {
                    ret::VERIFICATION_FAILURE
                }
            }
        }

        paste! {
        #[no_mangle]
        pub extern "C" fn [<$pc _keygen_from_seed>] (
            seed: Option<&slh_dsa_keygen_seed>,
            public_out: Option<&mut $pc::c_public_key>,
            private_out: Option<&mut $pc::c_private_key>,
        ) -> u8 {
            $pc::keygen(seed, public_out, private_out)
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _get_public_key>] (
            private: Option<&$pc::c_private_key>,
            public_out: Option<&mut $pc::c_public_key>,
        ) -> u8 {
            $pc::get_public_key(private, public_out)
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _sign_with_seed>] (
            private: Option<&$pc::c_private_key>,
            message: *const u8,
            message_size: usize,
            context: *const u8,
            context_size: usize,
            seed: Option<&slh_dsa_sign_seed>,
            hedged: u8,
            signature_out: Option<&mut $pc::c_signature>,
        ) -> u8 {
            $pc::sign(private, message, message_size, context, context_size, signature_out, seed, hedged)
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _verify>] (
            public: Option<&$pc::c_public_key>,
            signature: Option<&$pc::c_signature>,
            message: *const u8,
            message_size: usize,
            context: *const u8,
            context_size: usize,
        ) -> u8 {
            $pc::verify(public, signature, message, message_size, context, context_size)
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _hash_sign_with_seed>] (
            private: Option<&$pc::c_private_key>,
            hash: *const u8,
            hash_size: usize,
            context: *const u8,
            context_size: usize,
            hash_oid: *const u8,
            hash_oid_size: usize,
            seed: Option<&slh_dsa_sign_seed>,
            hedged: u8,
            signature_out: Option<&mut $pc::c_signature>,
        ) -> u8 {
            $pc::hash_sign(
                private, hash, hash_size, context, context_size, hash_oid, hash_oid_size,
                signature_out, seed, hedged,
            )
        }

        #[no_mangle]
        pub extern "C" fn [<$pc _hash_verify>] (
            public: Option<&$pc::c_public_key>,
            signature: Option<&$pc::c_signature>,
            hash: *const u8,
            hash_size: usize,
            context: *const u8,
            context_size: usize,
            hash_oid: *const u8,
            hash_oid_size: usize,
        ) -> u8 {
            $pc::hash_verify(
                public, signature, hash, hash_size, context, context_size, hash_oid, hash_oid_size,
            )
        }
        }
    };
}

parameter_set!(slh_dsa_sha2_128s);
parameter_set!(slh_dsa_sha2_128f);
parameter_set!(slh_dsa_shake_128s);
parameter_set!(slh_dsa_shake_128f);
