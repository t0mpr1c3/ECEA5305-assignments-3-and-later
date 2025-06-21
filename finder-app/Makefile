CC=gcc
CROSS_COMPILE=
CWD:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
cross-compiler-dir=$(CWD)/../../../assignments-3-and-later-t0mpr1c3/arm-cross-compiler/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu/bin

ifneq ($(CROSS_COMPILE),)
	CC=$(CROSS_COMPILE)gcc
endif

writer: writer.o
	$(CC) -o writer writer.o

writer.o: writer.c
	$(CC) -c writer.c -o writer.o

.PHONY: clean
clean:
	rm -f writer writer.o
