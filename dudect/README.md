Constant-time measurement of `fips205` key generation and signing with
[dudect-bencher](https://docs.rs/dudect-bencher/latest/dudect_bencher/). Each sample generates an
SLH-DSA-SHA2-128s key pair and makes a hedged signature with it, twice. The two classes use different
fixed seeds and signing randomness (every byte 0xAA, or every byte 0x55) and alternate sample by
sample, so a timing difference between two keys shows up as a large t-value. Results depend on the
machine and configuration; they are evidence, not proof.

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
October 14, 2026
13th Gen Intel® Core™ i7-13700K × 24  Circa 2022  Rust 1.98.1  fips205 v0.5.0

$ cd dudect  # this directory
$ cargo +stable clean
     Removed 0 files
$ time RUSTFLAGS="-C target-cpu=native" taskset -c 12 cargo +stable run --release  # A ~4 hour run on one P-core

...
    Finished `release` profile [optimized] target(s) in 15.08s
     Running `target/release/fips205-dudect`

running 1 bench
bench keygen_and_sign seeded with 0x24a4358283bfb2f3
bench keygen_and_sign ... : n == +0.042M, max t = +2.29489, max tau = +0.01115, (5/tau)^2 = 201152

dudect benches complete


real	237m44.099s
user	237m42.420s
sys	0m1.175s
~~~
