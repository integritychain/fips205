#![no_main]
use libfuzzer_sys::fuzz_target;
use fips205::{
    slh_dsa_sha2_128f,  // Using sha2_128f as an example parameter set
    traits::Signer,
    Ph,
};
use rand_core::OsRng;

// Wrapper struct to help organize the fuzz input
#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzInput {
    message: Vec<u8>,
    context: Vec<u8>,
    hedged: bool,
    use_hash: bool,
    hash_function: u8,  // We'll map this to Ph variants
}

fuzz_target!(|input: FuzzInput| {
    // Generate a keypair first (using real RNG for this part)
    if let Ok((_, sk)) = slh_dsa_sha2_128f::try_keygen() {
        // Map the hash function input to actual Ph variants
        let ph = match input.hash_function % 3 {
            0 => Ph::SHA256,
            1 => Ph::SHA512,
            _ => Ph::SHAKE256,
        };

        // Test regular signing
        let _ = sk.try_sign_with_rng(
            &mut OsRng,
            &input.message,
            &input.context[..input.context.len() % 255],
            input.hedged
        );

        // Test hash signing
        if input.use_hash {
            let _ = sk.try_hash_sign_with_rng(
                &mut OsRng,
                &input.message,
                &input.context[..input.context.len() % 255],
                &ph,
                input.hedged
            );
        }

        // Test public key derivation
        let _pk = sk.get_public_key();
    }
});

