CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: HEAP-0023
HEAP-0023: HEAP-0023.c
	$(CC) $(CFLAGS) -o $@ $<
clean:; rm -f HEAP-0023 *.o
