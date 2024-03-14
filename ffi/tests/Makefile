SO_LOCATION = ../../target/debug
FEATURES = slh_dsa_sha2_128f
FRAMES = public_key private_key signature sign verify keygen

BASELINES=$(foreach sz, $(FEATURES), baseline-$(sz))
CHECKS=$(foreach sz, $(FEATURES), runtest-$(sz))

check: $(CHECKS)

runtest-%: baseline-%
	LD_LIBRARY_PATH=$(SO_LOCATION) ./$<

baseline-%: baseline.c ../fips205.h
	$(CC) -o $@ -g -D SLHDSA=$* $(foreach v, $(FRAMES),-D SLHDSA_$(v)=$*_$(v)) -Werror -Wall -pedantic -L $(SO_LOCATION) $< -Wall -lfips205

clean:
	rm -f $(BASELINES)

.PHONY: clean check