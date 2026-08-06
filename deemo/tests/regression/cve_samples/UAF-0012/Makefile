CC ?= gcc; CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: UAF-0012; UAF-0012: UAF-0012.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f UAF-0012 *.o
