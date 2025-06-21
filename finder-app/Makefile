CC=gcc
CROSS_COMPILE=
cross-compiler-dir=/home/tom/arm-cross-compiler/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu/bin

ifneq ($(CROSS_COMPILE),)
	CC=$(cross-compiler-dir)/$(CROSS_COMPILE)gcc
endif

writer: writer.o
	$(CC) -o writer writer.o

writer.o: writer.c
	$(CC) -c writer.c -o writer.o

.PHONY: clean
clean:
	rm -f writer writer.o
