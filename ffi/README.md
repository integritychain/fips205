FIPS 205 FFI

Thank you to Daniel Kahn Gillmor <dkg@fifthhorseman.net> for the FIPS 203 example.

This is a work in progress, and currently only implements `slh_dsa_sha2_128f` until A) more 
testing has been developed, B) better integration with build flow.

~~~
To generate the C bindings...

$ cd ffi    # here
$ cargo build
$ cd tests
$ make


For Python (after generating the bindings)
$ python3 fips205.py
~~~