
Figure-of-merit ... no particular care taken to disable turbo boost etc

~~~
// $ RUSTFLAGS="-C target-cpu=native" cargo bench
// Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

// Mar 10 2024

sha2_128f  keygen       time:   [1.8046 ms 1.8049 ms 1.8053 ms]
sha2_192f  keygen       time:   [2.6420 ms 2.6425 ms 2.6432 ms]
sha2_256f  keygen       time:   [6.9202 ms 6.9300 ms 6.9481 ms]
shake_128f keygen       time:   [2.9981 ms 3.0007 ms 3.0050 ms]
shake_192f keygen       time:   [4.2558 ms 4.2562 ms 4.2568 ms]
shake_256f keygen       time:   [11.221 ms 11.236 ms 11.266 ms]
sha2_128s  keygen       time:   [115.98 ms 116.09 ms 116.20 ms]
sha2_192s  keygen       time:   [169.23 ms 169.36 ms 169.49 ms]
sha2_256s  keygen       time:   [110.80 ms 110.83 ms 110.86 ms]
shake_128s keygen       time:   [186.05 ms 186.39 ms 186.98 ms]
shake_192s keygen       time:   [272.52 ms 272.68 ms 272.86 ms]
shake_256s keygen       time:   [178.79 ms 178.95 ms 179.17 ms]

sha2_128f  sign         time:   [42.183 ms 42.204 ms 42.239 ms]
sha2_192f  sign         time:   [69.770 ms 69.801 ms 69.859 ms]
sha2_256f  sign         time:   [142.39 ms 142.45 ms 142.54 ms]
shake_128f sign         time:   [67.953 ms 67.966 ms 67.986 ms]
shake_192f sign         time:   [109.94 ms 109.95 ms 109.96 ms]
shake_256f sign         time:   [224.70 ms 224.71 ms 224.73 ms]
sha2_128s  sign         time:   [878.51 ms 878.70 ms 878.91 ms]
sha2_192s  sign         time:   [1.5740 s 1.5750 s 1.5761 s]
sha2_256s  sign         time:   [1.3848 s 1.3855 s 1.3865 s]
shake_128s sign         time:   [1.4197 s 1.4206 s 1.4216 s]
shake_192s sign         time:   [2.4545 s 2.4554 s 2.4565 s]
shake_256s sign         time:   [2.1544 s 2.1550 s 2.1557 s]

sha2_128f  verify       time:   [2.5928 ms 2.5939 ms 2.5958 ms]
sha2_192f  verify       time:   [3.7586 ms 3.7621 ms 3.7659 ms]
sha2_256f  verify       time:   [3.8196 ms 3.8216 ms 3.8242 ms]
shake_128f verify       time:   [4.0462 ms 4.0494 ms 4.0542 ms]
shake_192f verify       time:   [5.9527 ms 5.9531 ms 5.9536 ms]
shake_256f verify       time:   [5.9491 ms 5.9501 ms 5.9513 ms]
sha2_128s  verify       time:   [871.01 µs 871.07 µs 871.15 µs]
sha2_192s  verify       time:   [1.2818 ms 1.2832 ms 1.2846 ms]
sha2_256s  verify       time:   [1.8911 ms 1.8925 ms 1.8942 ms]
shake_128s verify       time:   [1.4506 ms 1.4513 ms 1.4522 ms]
shake_192s verify       time:   [2.1333 ms 2.1342 ms 2.1355 ms]
shake_256s verify       time:   [2.8122 ms 2.8139 ms 2.8161 ms]
~~~