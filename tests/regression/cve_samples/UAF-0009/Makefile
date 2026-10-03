CC ?= gcc; CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: UAF-0009; UAF-0009: UAF-0009.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f UAF-0009 *.o
