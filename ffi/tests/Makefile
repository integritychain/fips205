#!/usr/bin/make -f

# Usage: (cargo build -p fips205-ffi && cd tests && make)

# If the library and its development headers are installed system-wide,
# run the tests with:
#
#  (cd tests && make AS_INSTALLED=true)

SETS = sha2_128s sha2_128f shake_128s shake_128f
# Link name produced by cargo (libfips205.so / .dylib). ELF SONAME from
# build.rs is libfips205.so.0 — see RUNTIME_LIB below.
LINK_LIB = libfips205.$(SO_EXT)

OS := $(shell uname)

    CXXFLAGS += -DLINUX
ifeq ($(OS), Darwin)
    SO_EXT = dylib
else
	SO_EXT = so
endif

all: check

# adjustments for testing the local debug or release build:
ifneq ($(AS_INSTALLED),true)
SO_LOCATIONS = $(foreach w,.. ../..,$(foreach x,release debug,$w/target/$x $w/target/*/$x))
SO_LOCATION = $(dir $(firstword $(foreach d,$(SO_LOCATIONS),$(wildcard $d/$(LINK_LIB)))))

COMPILE_FLAGS = -Wl,-rpath,$(SO_LOCATION) -L $(SO_LOCATION) -I..
RUN_PREFIX = LD_LIBRARY_PATH=$(SO_LOCATION)
ifeq ($(OS), Darwin)
ADDITIONAL_RUN_DEPENDS = $(SO_LOCATION)$(LINK_LIB)
else
# cargo emits libfips205.so, but build.rs sets ELF SONAME to libfips205.so.0,
# so the loader looks for the versioned name at runtime.
ADDITIONAL_RUN_DEPENDS = $(SO_LOCATION)libfips205.so.0
$(SO_LOCATION)libfips205.so.0: $(SO_LOCATION)$(LINK_LIB)
	ln -sfn $(LINK_LIB) $@
endif
endif

BASELINES=$(foreach sz, $(SETS), baseline-$(sz))
CHECKS=$(foreach sz, $(SETS), run-baseline-$(sz)) run-link-two

check: $(CHECKS)

run-%: % $(ADDITIONAL_RUN_DEPENDS)
	$(RUN_PREFIX) ./$<

baseline-%: baseline.c ../fips205.h
	$(CC) -o $@ -g -DPFX=slh_dsa_$* -Werror -Wall -pedantic $< $(COMPILE_FLAGS) -lfips205

link-two: two_a.c two_b.c ../fips205.h
	$(CC) -o $@ -g -Werror -Wall -pedantic two_a.c two_b.c $(COMPILE_FLAGS) -lfips205

clean:
	rm -f $(BASELINES) link-two $(ADDITIONAL_RUN_DEPENDS)

.PHONY: clean check all
