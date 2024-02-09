use crate::types::Adrs;
use generic_array::{ArrayLength, GenericArray};

// TODO: We can do a bit better extracting common functionality versus parameter sets...


// Holds hasher function references; constructed by each wrapper
#[allow(clippy::type_complexity)]
pub(crate) struct Hashers<K: ArrayLength, LEN: ArrayLength, M: ArrayLength, N: ArrayLength> {
    pub(crate) h_msg: fn(&[u8], &[u8], &[u8], &[u8]) -> GenericArray<u8, M>,
    pub(crate) prf: fn(&[u8], &[u8], &Adrs) -> GenericArray<u8, N>,
    pub(crate) prf_msg: fn(&[u8], &[u8], &[u8]) -> GenericArray<u8, N>,
    pub(crate) f: fn(&[u8], &Adrs, &[u8]) -> GenericArray<u8, N>,
    pub(crate) h: fn(&[u8], &Adrs, &[u8], &[u8]) -> GenericArray<u8, N>,
    pub(crate) t_l:
        fn(&[u8], &Adrs, &GenericArray<GenericArray<u8, N>, LEN>) -> GenericArray<u8, N>,
    pub(crate) t_len:
        fn(&[u8], &Adrs, &GenericArray<GenericArray<u8, N>, K>) -> GenericArray<u8, N>,
}


#[cfg(any(
    feature = "slh_dsa_shake_128f",
    feature = "slh_dsa_shake_128s",
    feature = "slh_dsa_shake_192f",
    feature = "slh_dsa_shake_192s",
    feature = "slh_dsa_shake_256f",
    feature = "slh_dsa_shake_256s"
))]
pub(crate) mod shake {
    use crate::types::Adrs;
    use generic_array::{ArrayLength, GenericArray};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;


    #[allow(clippy::module_name_repetitions)]
    pub fn shake256(input: &[&[u8]], out: &mut [u8]) {
        let mut hasher = Shake256::default();
        input.iter().for_each(|item| hasher.update(item));
        let mut reader = hasher.finalize_xof();
        reader.read(out);
    }


    pub(crate) fn h_msg<M: ArrayLength>(
        r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8],
    ) -> GenericArray<u8, M> {
        let mut digest: GenericArray<u8, M> = GenericArray::default();
        shake256(&[&r, &pk_seed, &pk_root, m], &mut digest);
        digest
    }


    #[allow(clippy::similar_names)] // pk_seed and sk_seed
    pub(crate) fn prf<N: ArrayLength>(
        pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs,
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        shake256(&[pk_seed, &adrs.to_32_bytes(), sk_seed], &mut digest); // Note that the spec swaps order of last to params
        digest
    }


    pub(crate) fn prf_msg<N: ArrayLength>(
        sk_prf: &[u8], opt_rand: &[u8], m: &[u8],
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        shake256(&[sk_prf, opt_rand, m], &mut digest);
        digest
    }


    pub(crate) fn f<N: ArrayLength>(pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        shake256(&[pk_seed, &adrs.to_32_bytes(), m1], &mut digest);
        digest
    }


    pub(crate) fn h<N: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, m1: &[u8], m2: &[u8],
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        shake256(&[pk_seed, &adrs.to_32_bytes(), m1, m2], &mut digest);
        digest
    }


    // Perhaps there is a more elegant way to covert ml into list of bytes
    pub(crate) fn t_l<X: ArrayLength, Y: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, ml: &GenericArray<GenericArray<u8, Y>, X>,
    ) -> GenericArray<u8, Y> {
        let mut hasher = Shake256::default();
        hasher.update(pk_seed);
        hasher.update(&adrs.to_32_bytes());
        ml.iter().for_each(|item| hasher.update(item));
        let mut reader = hasher.finalize_xof();
        let mut result = GenericArray::default();
        reader.read(&mut result);
        result
    }
}


#[cfg(any(feature = "slh_dsa_sha2_128f", feature = "slh_dsa_sha2_128s"))]
pub(crate) mod sha2_cat_1 {
    use crate::types::Adrs;
    use core::cmp::min;
    use generic_array::{ArrayLength, GenericArray};
    use sha2::{Digest, Sha256};


    pub fn sha2_256(input: &[&[u8]], out: &mut [u8]) {
        debug_assert!(out.len() <= 32);
        let mut hasher = Sha256::new();
        input.iter().for_each(|item| hasher.update(item));
        let result = hasher.finalize();
        out.copy_from_slice(&result[0..out.len()]);
    }


    pub(crate) fn h_msg<M: ArrayLength>(
        r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8],
    ) -> GenericArray<u8, M> {
        let mut digest1 = [0u8; 32];
        sha2_256(&[&r, &pk_seed, &pk_root, m], &mut digest1);
        let mut result: GenericArray<u8, M> = GenericArray::default();
        let mut start = 0;
        let mut counter = 0u32;
        while start < M::to_usize() {
            let mut tmp = [0u8; 32];
            sha2_256(&[&r, &pk_seed, &digest1, &counter.to_be_bytes()], &mut tmp);
            let len = min(M::to_usize() - start, 32);
            result[start..start + len].copy_from_slice(&tmp[0..len]);
            start += 32;
            counter += 1;
        }
        result
    }


    #[allow(clippy::similar_names)] // pk_seed and sk_seed
    pub(crate) fn prf<N: ArrayLength>(
        pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs,
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        let to_byte = [0u8; 64];
        sha2_256(
            &[
                pk_seed,
                &to_byte[0..(64 - N::to_usize())],
                &adrs.to_22_bytes(),
                sk_seed,
            ],
            &mut digest,
        ); // Note that the spec swaps order of last to params
        digest
    }


    pub fn hmac_sha_256(key: &[u8], a0: &[u8], b1: &[u8]) -> [u8; 32] {
        let k2 = key;
        let mut padded = [0x36; 64];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&padded[..]);
        inner_hasher.update(a0);
        inner_hasher.update(b1);
        for p in &mut padded {
            *p ^= 0x6a;
        }
        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&padded[..]);
        outer_hasher.update(inner_hasher.finalize());
        outer_hasher.finalize().into()
    }


    pub(crate) fn prf_msg<N: ArrayLength>(
        sk_prf: &[u8], opt_rand: &[u8], m: &[u8],
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        //sha2_256(&[sk_prf, opt_rand, m], &mut digest);
        let xxx = hmac_sha_256(sk_prf, opt_rand, m);
        digest.copy_from_slice(&xxx[0..N::to_usize()]);
        digest
    }


    pub(crate) fn f<N: ArrayLength>(pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        let to_byte = [0u8; 64];
        sha2_256(
            &[
                pk_seed,
                &to_byte[0..(64 - N::to_usize())],
                &adrs.to_22_bytes(),
                m1,
            ],
            &mut digest,
        );
        digest
    }


    pub(crate) fn h<N: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, m1: &[u8], m2: &[u8],
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        let to_byte = [0u8; 64];
        sha2_256(
            &[
                pk_seed,
                &to_byte[0..(64 - N::to_usize())],
                &adrs.to_22_bytes(),
                m1,
                m2,
            ],
            &mut digest,
        );
        digest
    }


    // Perhaps there is a more elegant way to covert ml into list of bytes
    pub(crate) fn t_l<LEN: ArrayLength, N: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, ml: &GenericArray<GenericArray<u8, N>, LEN>,
    ) -> GenericArray<u8, N> {
        let mut result = GenericArray::default();
        let to_byte = [0u8; 64];
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        hasher.update(&to_byte[0..(64 - N::to_usize())]);
        hasher.update(adrs.to_22_bytes());
        ml.iter().for_each(|item| hasher.update(item));
        let digest = hasher.finalize();
        result.copy_from_slice(&digest[0..N::to_usize()]);
        result
    }
}


#[cfg(any(
    feature = "slh_dsa_sha2_192f",
    feature = "slh_dsa_sha2_192s",
    feature = "slh_dsa_sha2_256f",
    feature = "slh_dsa_sha2_256s"
))]
pub(crate) mod sha2_cat_3_5 {
    use crate::types::Adrs;
    use core::cmp::min;
    use generic_array::{ArrayLength, GenericArray};
    use sha2::{Digest, Sha256, Sha512};


    pub fn sha2_256(input: &[&[u8]], out: &mut [u8]) {
        debug_assert!(out.len() <= 32);
        let mut hasher = Sha256::new();
        input.iter().for_each(|item| hasher.update(item));
        let result = hasher.finalize();
        out.copy_from_slice(&result[0..out.len()]);
    }


    pub fn sha2_512(input: &[&[u8]], out: &mut [u8]) {
        debug_assert!(out.len() <= 64);
        let mut hasher = Sha512::new();
        input.iter().for_each(|item| hasher.update(item));
        let result = hasher.finalize();
        out.copy_from_slice(&result[0..out.len()]);
    }


    pub(crate) fn h_msg<M: ArrayLength>(
        r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8],
    ) -> GenericArray<u8, M> {
        let mut digest1 = [0u8; 64];
        sha2_512(&[&r, &pk_seed, &pk_root, m], &mut digest1);
        let mut result: GenericArray<u8, M> = GenericArray::default();
        let mut start = 0;
        let mut counter = 0u32;
        while start < M::to_usize() {
            let mut tmp = [0u8; 64];
            sha2_512(&[&r, &pk_seed, &digest1, &counter.to_be_bytes()], &mut tmp);
            let len = min(M::to_usize() - start, 64);
            result[start..start + len].copy_from_slice(&tmp[0..len]);
            start += 64;
            counter += 1;
        }
        result
    }


    #[allow(clippy::similar_names)] // pk_seed and sk_seed
    pub(crate) fn prf<N: ArrayLength>(
        pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs,
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        let to_byte = [0u8; 64];
        sha2_256(
            &[
                pk_seed,
                &to_byte[0..(64 - N::to_usize())],
                &adrs.to_22_bytes(),
                sk_seed,
            ],
            &mut digest,
        ); // Note that the spec swaps order of last to params
        digest
    }


    pub fn hmac_sha_512(key: &[u8], a0: &[u8], b1: &[u8]) -> [u8; 64] {
        let k2 = key;
        let mut padded = [0x36; 128];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        let mut inner_hasher = Sha512::new();
        inner_hasher.update(&padded[..]);
        inner_hasher.update(a0);
        inner_hasher.update(b1);
        for p in &mut padded {
            *p ^= 0x6a;
        }
        let mut outer_hasher = Sha512::new();
        outer_hasher.update(&padded[..]);
        outer_hasher.update(inner_hasher.finalize());
        outer_hasher.finalize().into()
    }


    pub(crate) fn prf_msg<N: ArrayLength>(
        sk_prf: &[u8], opt_rand: &[u8], m: &[u8],
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        let xxx = hmac_sha_512(sk_prf, opt_rand, m);
        digest.copy_from_slice(&xxx[0..N::to_usize()]);
        digest
    }


    pub(crate) fn f<N: ArrayLength>(pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        let to_byte = [0u8; 64];
        sha2_256(
            &[
                pk_seed,
                &to_byte[0..(64 - N::to_usize())],
                &adrs.to_22_bytes(),
                m1,
            ],
            &mut digest,
        );
        digest
    }


    pub(crate) fn h<N: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, m1: &[u8], m2: &[u8],
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        let to_byte = [0u8; 128];
        sha2_512(
            &[
                pk_seed,
                &to_byte[0..(128 - N::to_usize())],
                &adrs.to_22_bytes(),
                m1,
                m2,
            ],
            &mut digest,
        );
        digest
    }


    // Perhaps there is a more elegant way to covert ml into list of bytes
    pub(crate) fn t_l<LEN: ArrayLength, N: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, ml: &GenericArray<GenericArray<u8, N>, LEN>,
    ) -> GenericArray<u8, N> {
        let mut result = GenericArray::default();
        let to_byte = [0u8; 128];
        let mut hasher = Sha512::new();
        hasher.update(pk_seed);
        hasher.update(&to_byte[0..(128 - N::to_usize())]);
        hasher.update(adrs.to_22_bytes());
        ml.iter().for_each(|item| hasher.update(item));
        let digest = hasher.finalize();
        result.copy_from_slice(&digest[0..N::to_usize()]);
        result
    }
}
