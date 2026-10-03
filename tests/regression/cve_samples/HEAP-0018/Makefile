CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: HEAP-0018
HEAP-0018: HEAP-0018.c
	$(CC) $(CFLAGS) -o $@ $<
clean:; rm -f HEAP-0018 *.o
