#![no_std]
#![deny(clippy::pedantic)]
#![deny(warnings)]
#![deny(missing_docs)]
#![allow(dead_code)]

//! TKTK crate doc

extern crate alloc;


mod algs;
mod traits;
mod types;

/// to be deleted
#[must_use]
pub fn add(left: usize, right: usize) -> usize { left + right }

struct Context {
    lgw: u32,
    w: usize,
    len1: usize,
    len2: usize,
    len: usize,
}


macro_rules! functionality {
    () => {
        use crate::traits::PK;
        use crate::types::SlhDsaSig;
        use crate::Context;
        use generic_array::typenum::{U16, U5};
        use zeroize::{Zeroize, ZeroizeOnDrop};
        // ----- 'EXTERNAL' DATA TYPES -----

        const W: usize = 2_usize.pow(LGW);
        const LEN1: usize = (8 * N).div_ceil(LGW as usize);
        const LEN2: usize = ((LEN1 * (W - 1)).ilog2() / LGW) as usize + 1;
        const LEN: usize = LEN1 + LEN2;

        static CONTEXT: Context = Context { lgw: LGW, w: W, len1: LEN1, len2: LEN2, len: LEN };


        fn sign() -> SlhDsaSig<U5, U5, U16> { SlhDsaSig::<U5, U5, U16>::default() }

        /// Correctly sized private key specific to the target security parameter set. <br>
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct PrivateKey {
            pub(crate) sk_seed: [u8; N],
            sk_prf: [u8; N],
            pk_seed: [u8; N],
            pk_root: [u8; N],
        }

        impl PK for PrivateKey {
            type Seed = [u8; N];

            fn seed(&self) -> [u8; N] { self.sk_seed }
        }
    };
}

/// TKTK
#[cfg(feature = "slh_dsa_sha2_128s")]
pub mod slh_dsa_sha2_128s {
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
