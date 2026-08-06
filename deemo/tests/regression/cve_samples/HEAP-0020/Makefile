CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: HEAP-0020
HEAP-0020: HEAP-0020.c
	$(CC) $(CFLAGS) -o $@ $<
clean:; rm -f HEAP-0020 *.o
