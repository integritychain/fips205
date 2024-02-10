This needs work...

See https://docs.rs/dudect-bencher/latest/dudect_bencher/

Dudect can indicate something terribly wrong, but not too much else.


~~~
$ cargo run --release -- --continuous sign
    Finished release [optimized] target(s) in 7.34s
     Running `target/release/fips205-dudect --continuous sign`
running 1 benchmark continuously
bench sign seeded with 0x2e4df99cf3c2b95b
bench sign ... : n == +0.000M, max t = +1.89036, max tau = +0.56996, (5/tau)^2 = 76
bench sign ... : n == +0.000M, max t = +3.41458, max tau = +0.72799, (5/tau)^2 = 47
bench sign ... : n == +0.000M, max t = +3.15437, max tau = +0.56654, (5/tau)^2 = 77
bench sign ... : n == +0.000M, max t = +3.68377, max tau = +0.57531, (5/tau)^2 = 75
bench sign ... : n == +0.000M, max t = +4.21598, max tau = +0.48046, (5/tau)^2 = 108
bench sign ... : n == +0.000M, max t = +3.89742, max tau = +0.39987, (5/tau)^2 = 156
bench sign ... : n == +0.000M, max t = +4.01349, max tau = +0.37924, (5/tau)^2 = 173
bench sign ... : n == +0.000M, max t = +3.47164, max tau = +0.30566, (5/tau)^2 = 267
bench sign ... : n == +0.000M, max t = +3.55797, max tau = +0.29547, (5/tau)^2 = 286
bench sign ... : n == +0.000M, max t = +2.97639, max tau = +0.23604, (5/tau)^2 = 448
~~~

