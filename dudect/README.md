An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
October 3, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017  Rust 1.81

$ cd dudect  # this directory
$ cargo clean
$ time RUSTFLAGS="-C target-cpu=native" cargo run --release  # A ~11 hour run

...
   Compiling fips205 v0.4.0 (/home/eric/work/fips205)
   Compiling fips205-dudect v0.4.0 (/home/eric/work/fips205/dudect)
    Finished `release` profile [optimized] target(s) in 12.04s
     Running `target/release/fips205-dudect`

running 1 bench
bench keygen_and_sign seeded with 0x54522172d8fff6c0
bench keygen_and_sign ... : n == +0.007M, max t = +3.04638, max tau = +0.03693, (5/tau)^2 = 18331

dudect benches complete


real	660m35.132s
user	660m47.614s
sys	0m2.662s
~~~
