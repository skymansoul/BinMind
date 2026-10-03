CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: HEAP-0022
HEAP-0022: HEAP-0022.c
	$(CC) $(CFLAGS) -o $@ $<
clean:; rm -f HEAP-0022 *.o
