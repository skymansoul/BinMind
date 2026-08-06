CC ?= gcc; CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: UAF-0011; UAF-0011: UAF-0011.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f UAF-0011 *.o
