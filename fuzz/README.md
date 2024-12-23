This is a work in progress, but good results currently.

Harness code is in fuzz/fuzz_targets/*. The Cargo.toml file specifies that overflow-checks and 
debug-assertions are enabled (so the fuzzer can find these panics).

See <https://rust-fuzz.github.io/book/introduction.html>

~~~
$ cd fuzz  # this directory; you may need to install cargo fuzz
$ rustup default nightly
$ mkdir -p corpus/fuzz_sign
$ dd if=/dev/zero bs=1 count=6292 > corpus/fuzz_sign/seed0
$ for i in $(seq 1 9); do head -c 6292 </dev/urandom > corpus/fuzz_sign/seed$i; done
$ mkdir -p corpus/fuzz_verify
$ dd if=/dev/zero bs=1 count=6292 > corpus/fuzz_verify/seed0
$ for i in $(seq 0 9); do head -c 6292 </dev/urandom > corpus/fuzz_verify/seed$i; done

$ cargo fuzz run fuzz_sign -j 4 -- -max_total_time=1000

...
#205: cov: 2486 ft: 4394 corp: 10 exec/s: 0 oom/timeout/crash: 0/0/0 time: 965s job: 51 dft_time: 0
#209: cov: 2486 ft: 4394 corp: 10 exec/s: 0 oom/timeout/crash: 0/0/0 time: 965s job: 49 dft_time: 0
#215: cov: 2486 ft: 4394 corp: 10 exec/s: 0 oom/timeout/crash: 0/0/0 time: 980s job: 52 dft_time: 0
#219: cov: 2486 ft: 4394 corp: 10 exec/s: 0 oom/timeout/crash: 0/0/0 time: 1020s job: 54 dft_time: 0
INFO: fuzzed for 1020 seconds, wrapping up soon
INFO: exiting: 0 time: 1050s



$ cargo fuzz run fuzz_verify -j 4 -- -max_total_time=1000

...
#307: cov: 18818 ft: 12996 corp: 30 exec/s 0 oom/timeout/crash: 0/0/0 time: 915s job: 57 dft_time: 0
#314: cov: 18818 ft: 13023 corp: 32 exec/s 0 oom/timeout/crash: 0/0/0 time: 934s job: 58 dft_time: 0
#321: cov: 18818 ft: 13040 corp: 33 exec/s 0 oom/timeout/crash: 0/0/0 time: 945s job: 59 dft_time: 0
#328: cov: 18818 ft: 13063 corp: 34 exec/s 0 oom/timeout/crash: 0/0/0 time: 964s job: 60 dft_time: 0
#336: cov: 18818 ft: 13078 corp: 35 exec/s 0 oom/timeout/crash: 0/0/0 time: 998s job: 61 dft_time: 0
INFO: fuzzed for 1018 seconds, wrapping up soon
INFO: exiting: 0 time: 1031s
~~~

Coverage status is a work-in-progress (note that verify also exercises signing); see FIPS 204 code for example runs
