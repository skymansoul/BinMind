CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: HEAP-0017
HEAP-0017: HEAP-0017.c
	$(CC) $(CFLAGS) -o $@ $<
clean:; rm -f HEAP-0017 *.o
