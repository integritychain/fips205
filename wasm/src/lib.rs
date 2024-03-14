use wasm_bindgen::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use fips205::slh_dsa_sha2_128f;
use fips205::traits::{SerDes, Signer, Verifier};


#[wasm_bindgen]
pub fn sign(message: &str) -> String {
    let seed = 123;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
    let randomize = true;

    let (pk, sk) = slh_dsa_sha2_128f::try_keygen_with_rng_vt(&mut rng).expect("keygen failed");
    let sig = sk.try_sign_with_rng_ct(&mut rng, message.as_ref(), randomize).expect("sign failed");
    assert!(pk.try_verify_vt(message.as_ref(), &sig).expect("verify error"), "verify failed");

    let sk_hex = hex::encode(&sk.into_bytes());
    let sig_hex = hex::encode(&sig);
    let pk_hex = hex::encode(&pk.into_bytes());

    let s0 = format!("The message to sign is: {}\n", message);
    let s1 = format!("The seed used to generate the keys is: {}\n\n", seed);
    let s2 = format!("The generated public||private key is: {}\n", sk_hex);
    let s3 = format!("Using that private key, the calculated signature is: {}\n\n", sig_hex);
    let s4 = format!("The generated public key is: {}\n", pk_hex);
    let s5 = "The public key verifies the signature on the message.";  // because the above assert! passed

    (s0 + &s1 + &s2 + &s3 + &s4 + &s5).into()
}
