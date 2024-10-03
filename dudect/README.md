An example constant-time workbench. It can be sensitive to config/defaults, so is
not entirely definitive. A work in progress.

See <https://docs.rs/dudect-bencher/latest/dudect_bencher/>

> t-values greater than 5 are generally considered a good indication that the function is not constant time. t-values less than 5 does not necessarily imply that the function is constant-time, since there may be other input distributions under which the function behaves significantly differently.

~~~
October 3, 2024
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8  Circa 2017  Rust 1.81

$ cd dudect  # this directory
$ cargo clean
$ time RUSTFLAGS="-C target-cpu=native" cargo run --release

...
   Compiling fips205-dudect v0.4.0 (/home/eric/work/fips205/dudect)
    Finished `release` profile [optimized] target(s) in 7.36s
     Running `target/release/fips205-dudect`

running 1 bench
bench keygen_and_sign seeded with 0x89b5d1d7e0207f97
bench keygen_and_sign ... : n == +0.001M, max t = -1.03786, max tau = -0.03383, (5/tau)^2 = 21840

dudect benches complete


real	63m43.206s
user	64m12.095s
sys	0m2.511s
~~~
