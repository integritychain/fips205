use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
use fips205::traits::Signer;

fn sign(runner: &mut CtRunner, mut _rng: &mut BenchRng) {
    const ITERATIONS_OUTER: usize = 10;
    const ITERATIONS_INNER: usize = 1;

    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    let (_pk1, sk1) = slh_dsa_shake_128s::try_keygen().unwrap();  // Generate both public and secret keys
    let (_pk2, sk2) = slh_dsa_shake_128s::try_keygen().unwrap();  // Generate both public and secret keys

    let mut inputs: Vec<slh_dsa_shake_128s::PrivateKey> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS_OUTER {
        inputs.push(sk1.clone());
        classes.push(Class::Left);
    }

    for _ in 0..ITERATIONS_OUTER {
        inputs.push(sk2.clone());
        classes.push(Class::Right);
    }

    for (class, input) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            for _ in 0..ITERATIONS_INNER {
                let _ = input.try_sign(&message, true);
            }
        })
    }
}

ctbench_main!(sign);
