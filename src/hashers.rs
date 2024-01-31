use crate::types::Adrs;
use generic_array::{ArrayLength, GenericArray};

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
    feature = "slh_dsa_sha2_128s",  // TODO: Wrong!! fix
    feature = "slh_dsa_shake_128f",
    feature = "slh_dsa_shake_128s",
    feature = "slh_dsa_shake_192f",
    feature = "slh_dsa_shake_192s",
    feature = "slh_dsa_shake_256f",
    feature = "slh_dsa_shake_256s"
))]
#[allow(dead_code)]
pub(crate) mod shake {
    use crate::types::Adrs;
    use generic_array::{ArrayLength, GenericArray};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;


    fn shake256_a(input: &[&[u8]], out: &mut [u8]) {
        let mut hasher = Shake256::default();
        input.iter().for_each(|item| hasher.update(item));
        let mut reader = hasher.finalize_xof();
        reader.read(out);
    }

    pub(crate) fn h_msg<M: ArrayLength>(
        r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8],
    ) -> GenericArray<u8, M> {
        let mut digest: GenericArray<u8, M> = GenericArray::default();
        shake256_a(&[&r, &pk_seed, &pk_root, m], &mut digest);
        digest
    }

    pub(crate) fn prf<N: ArrayLength>(
        pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs,
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        shake256_a(&[pk_seed, &adrs.to_32_bytes(), sk_seed], &mut digest); // Note that the spec swaps order of last to params
        digest
    }

    pub(crate) fn prf_msg<N: ArrayLength>(
        sk_prf: &[u8], opt_rand: &[u8], m: &[u8],
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        shake256_a(&[sk_prf, opt_rand, m], &mut digest);
        digest
    }

    pub(crate) fn f<N: ArrayLength>(pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        shake256_a(&[pk_seed, &adrs.to_32_bytes(), m1], &mut digest);
        digest
    }

    pub(crate) fn h<N: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, m1: &[u8], m2: &[u8],
    ) -> GenericArray<u8, N> {
        let mut digest: GenericArray<u8, N> = GenericArray::default();
        shake256_a(&[pk_seed, &adrs.to_32_bytes(), m1, m2], &mut digest);
        digest
    }

    // Until a more elegant way is found to covert ml into list of bytes
    pub(crate) fn t_l<LEN: ArrayLength, N: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, ml: &GenericArray<GenericArray<u8, N>, LEN>,
    ) -> GenericArray<u8, N> {
        let mut hasher = Shake256::default();
        hasher.update(pk_seed);
        hasher.update(&adrs.to_32_bytes());
        ml.iter().for_each(|item| hasher.update(item));
        let mut reader = hasher.finalize_xof();
        let mut result = GenericArray::default();
        reader.read(&mut result);
        result
    }

    // TODO: Squash K and LEN versions
    // Until a more elegant way is found to covert ml into list of bytes
    pub(crate) fn t_len<K: ArrayLength, N: ArrayLength>(
        pk_seed: &[u8], adrs: &Adrs, ml: &GenericArray<GenericArray<u8, N>, K>,
    ) -> GenericArray<u8, N> {
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

pub(crate) mod sha2_cat_1 {
    use crate::types::Adrs;
    use generic_array::{ArrayLength, GenericArray};

    pub(crate) fn h_msg<M: ArrayLength>(
        _r: &[u8], _pk_seed: &[u8], _pk_root: &[u8], _m: &[u8],
    ) -> GenericArray<u8, M> {
        GenericArray::default()
    }

    pub(crate) fn prf<N: ArrayLength>(
        _pk_seed: &[u8], _sk_seed: &[u8], _adrs: &Adrs,
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    pub(crate) fn prf_msg<N: ArrayLength>(
        _sk_prf: &[u8], _opt_rand: &[u8], _m: &[u8],
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    pub(crate) fn f<N: ArrayLength>(
        _pk_seed: &[u8], _adrs: &Adrs, _m1: &[u8],
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    pub(crate) fn h<N: ArrayLength>(
        _pk_seed: &[u8], _adrs: &Adrs, _m1: &[u8], _m2: &[u8],
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    // Until a more elegant way is found to covert ml into list of bytes
    pub(crate) fn t_l<LEN: ArrayLength, N: ArrayLength>(
        _pk_seed: &[u8], _adrs: &Adrs, _ml: &GenericArray<GenericArray<u8, N>, LEN>,
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    // TODO: Squash K and LEN versions
    // Until a more elegant way is found to covert ml into list of bytes
    pub(crate) fn t_len<K: ArrayLength, N: ArrayLength>(
        _pk_seed: &[u8], _adrs: &Adrs, _ml: &GenericArray<GenericArray<u8, N>, K>,
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }
}


pub(crate) mod sha2_cat_3_5 {
    use crate::types::Adrs;
    use generic_array::{ArrayLength, GenericArray};

    pub(crate) fn h_msg<M: ArrayLength>(
        _r: &[u8], _pk_seed: &[u8], _pk_root: &[u8], _m: &[u8],
    ) -> GenericArray<u8, M> {
        GenericArray::default()
    }

    pub(crate) fn prf<N: ArrayLength>(
        _pk_seed: &[u8], _sk_seed: &[u8], _adrs: &Adrs,
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    pub(crate) fn prf_msg<N: ArrayLength>(
        _sk_prf: &[u8], _opt_rand: &[u8], _m: &[u8],
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    pub(crate) fn f<N: ArrayLength>(
        _pk_seed: &[u8], _adrs: &Adrs, _m1: &[u8],
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    pub(crate) fn h<N: ArrayLength>(
        _pk_seed: &[u8], _adrs: &Adrs, _m1: &[u8], _m2: &[u8],
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    // Until a more elegant way is found to covert ml into list of bytes
    pub(crate) fn t_l<LEN: ArrayLength, N: ArrayLength>(
        _pk_seed: &[u8], _adrs: &Adrs, _ml: &GenericArray<GenericArray<u8, N>, LEN>,
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }

    // TODO: Squash K and LEN versions
    // Until a more elegant way is found to covert ml into list of bytes
    pub(crate) fn t_len<K: ArrayLength, N: ArrayLength>(
        _pk_seed: &[u8], _adrs: &Adrs, _ml: &GenericArray<GenericArray<u8, N>, K>,
    ) -> GenericArray<u8, N> {
        GenericArray::default()
    }
}
