CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: HEAP-0021
HEAP-0021: HEAP-0021.c
	$(CC) $(CFLAGS) -o $@ $<
clean:; rm -f HEAP-0021 *.o
