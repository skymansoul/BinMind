CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: HEAP-0016
HEAP-0016: HEAP-0016.c
	$(CC) $(CFLAGS) -o $@ $<
clean:; rm -f HEAP-0016 *.o
