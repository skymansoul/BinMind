CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: HEAP-0024
HEAP-0024: HEAP-0024.c
	$(CC) $(CFLAGS) -o $@ $<
clean:; rm -f HEAP-0024 *.o
