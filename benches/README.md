Figure-of-merit only; no particular care has been taken to disable turbo-boost etc.
Note that constant-time restrictions on the implementation do impact performance.

~~~
October 1, 2026
13th Gen Intel® Core™ i7-13700K, Rust 1.85.1
Bench profile: opt-level 3, LTO, codegen-units 1, overflow checks off.
Turbo Boost was left enabled.

$ RUSTFLAGS="-C target-cpu=native" cargo bench --bench benchmark

sha2_128f  keygen       time:   [315.83 µs 315.95 µs 316.08 µs]
sha2_192f  keygen       time:   [530.10 µs 530.25 µs 530.39 µs]
sha2_256f  keygen       time:   [1.0517 ms 1.0521 ms 1.0525 ms]
shake_128f keygen       time:   [1.6899 ms 1.6941 ms 1.6980 ms]
shake_192f keygen       time:   [2.4966 ms 2.5062 ms 2.5174 ms]
shake_256f keygen       time:   [6.6860 ms 6.7259 ms 6.7730 ms]
sha2_128s  keygen       time:   [20.186 ms 20.188 ms 20.190 ms]
sha2_192s  keygen       time:   [33.893 ms 33.905 ms 33.923 ms]
sha2_256s  keygen       time:   [16.798 ms 16.816 ms 16.843 ms]
shake_128s keygen       time:   [107.14 ms 107.34 ms 107.55 ms]
shake_192s keygen       time:   [159.65 ms 160.12 ms 160.74 ms]
shake_256s keygen       time:   [103.06 ms 103.28 ms 103.57 ms]

sha2_128f  sign         time:   [7.4326 ms 7.4345 ms 7.4378 ms]
sha2_192f  sign         time:   [15.675 ms 15.675 ms 15.676 ms]
sha2_256f  sign         time:   [25.306 ms 25.319 ms 25.331 ms]
shake_128f sign         time:   [39.302 ms 39.579 ms 40.046 ms]
shake_192f sign         time:   [64.201 ms 64.342 ms 64.505 ms]
shake_256f sign         time:   [129.79 ms 130.14 ms 130.60 ms]
sha2_128s  sign         time:   [154.01 ms 154.02 ms 154.03 ms]
sha2_192s  sign         time:   [369.93 ms 369.94 ms 369.95 ms]
sha2_256s  sign         time:   [285.17 ms 285.29 ms 285.47 ms]
shake_128s sign         time:   [816.49 ms 818.62 ms 822.37 ms]
shake_192s sign         time:   [1.4296 s 1.4319 s 1.4352 s]
shake_256s sign         time:   [1.2308 s 1.2322 s 1.2345 s]

sha2_128f  verify       time:   [455.02 µs 455.07 µs 455.15 µs]
sha2_192f  verify       time:   [849.25 µs 849.39 µs 849.57 µs]
sha2_256f  verify       time:   [709.10 µs 709.17 µs 709.26 µs]
shake_128f verify       time:   [2.2483 ms 2.2490 ms 2.2498 ms]
shake_192f verify       time:   [3.4347 ms 3.4638 ms 3.5019 ms]
shake_256f verify       time:   [3.3624 ms 3.3636 ms 3.3649 ms]
sha2_128s  verify       time:   [156.32 µs 156.40 µs 156.51 µs]
sha2_192s  verify       time:   [326.73 µs 326.79 µs 326.85 µs]
sha2_256s  verify       time:   [387.29 µs 387.38 µs 387.50 µs]
shake_128s verify       time:   [792.04 µs 792.68 µs 793.41 µs]
shake_192s verify       time:   [1.1451 ms 1.1454 ms 1.1457 ms]
shake_256s verify       time:   [1.7177 ms 1.7254 ms 1.7355 ms]
~~~
