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
#11962: cov: 2075 ft: 2738 corp: 4 exec/s: 0 oom/timeout/crash: 0/0/0 time: 932s job: 27 dft_time: 0
#11965: cov: 2075 ft: 2738 corp: 4 exec/s: 0 oom/timeout/crash: 0/0/0 time: 986s job: 28 dft_time: 0
#11968: cov: 2075 ft: 2738 corp: 4 exec/s: 0 oom/timeout/crash: 0/0/0 time: 986s job: 29 dft_time: 0
#11971: cov: 2075 ft: 2738 corp: 4 exec/s: 0 oom/timeout/crash: 0/0/0 time: 991s job: 30 dft_time: 0
#11974: cov: 2075 ft: 2738 corp: 4 exec/s: 0 oom/timeout/crash: 0/0/0 time: 1046s job: 31 dft_time: 0
INFO: fuzzed for 1046 seconds, wrapping up soon
INFO: exiting: 0 time: 1104s
~~~

Coverage status is a work-in-progress; see FIPS 204 code for example runs
