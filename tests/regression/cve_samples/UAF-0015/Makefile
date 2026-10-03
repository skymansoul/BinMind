CC ?= gcc; CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: UAF-0015; UAF-0015: UAF-0015.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f UAF-0015 *.o
