CC ?= gcc; CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: UAF-0014; UAF-0014: UAF-0014.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f UAF-0014 *.o
