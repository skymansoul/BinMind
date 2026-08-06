CC ?= gcc; CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: UAF-0008; UAF-0008: UAF-0008.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f UAF-0008 *.o
