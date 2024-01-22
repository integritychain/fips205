#[cfg(test)]
mod tests {
    extern crate alloc;
    use hex::decode;

    use alloc::vec::Vec;
    //use rand::{Rng, SeedableRng};
    use rand_core::{CryptoRng, RngCore};


    struct TestRng {
        data: Vec<Vec<u8>>,
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 { unimplemented!() }

        fn next_u64(&mut self) -> u64 { unimplemented!() }

        fn fill_bytes(&mut self, out: &mut [u8]) {
            let x = self.data.pop().expect("TestRng problem");
            out.copy_from_slice(&x)
        }

        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(out);
            Ok(()) // panic on probs is OK
        }
    }

    impl CryptoRng for TestRng {}

    impl TestRng {
        fn new() -> Self { TestRng { data: Vec::new() } }

        fn push(&mut self, new_data: &[u8]) {
            let x = new_data.to_vec();
            self.data.push(x);
        }
    }


    use crate::slh_dsa_sha2_128s::{slh_keygen_with_rng, slh_sign_with_rng, slh_verify};

    #[test]
    fn vector_debug() {
        let m = decode("d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8").unwrap();
        let mut rnd = TestRng::new();
        let sk_seed = "7c9935a0b07694aa0c6d10e4db6b1add";
        let sk_prf = "2fd81a25ccb148032dcd739936737f2d";
        let pk_seed = "b505d7cfad1b497499323c8686325e47";
        let opt_rand = "33b3c07507e4201748494d832b6ee2a6";
        rnd.push(&decode(opt_rand).unwrap());
        rnd.push(&decode(pk_seed).unwrap());
        rnd.push(&decode(sk_prf).unwrap());
        rnd.push(&decode(sk_seed).unwrap());

        let (sk, pk) = slh_keygen_with_rng (&mut rnd).unwrap();
        assert_eq!(*decode("ac524902fc81f5032bc27b17d9261ebd").unwrap(), *sk.pk_root, "pk_root failed!!!!!!");

        let sig = slh_sign_with_rng(&mut rnd, &m, &sk, true).unwrap();
        assert_eq!(*decode("43f8eb75d58b652f779c5a0f5378709e").unwrap(), *sig.fors_sig.private_key_value[0], "fors_sig failed!!!");
        assert_eq!(*decode("ad62955228fdf4c3be9c22f601397a11").unwrap(), *sig.ht_sig.xmss_sigs[0].sig_wots.data[0], "fors_sig failed!!!");

        let result = slh_verify(&m, &sig, &pk);
        assert_eq!(result, true, "Signature did not verify!");
    }
}
