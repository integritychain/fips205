FIPS 205 FFI

Thank you to Daniel Kahn Gillmor <dkg@fifthhorseman.net> for the FIPS 203 example.

Currently only implemented for `slh_dsa_sha2_128f` until A) more testing has been developed, B) better integration with build flow.

~~~
$ cd ffi    # here
$ cargo build
$ cd tests
$ make
~~~