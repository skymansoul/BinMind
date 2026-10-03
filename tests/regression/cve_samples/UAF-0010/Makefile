CC ?= gcc; CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: UAF-0010; UAF-0010: UAF-0010.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f UAF-0010 *.o
