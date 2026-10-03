CC ?= gcc; CFLAGS ?= -O0 -g -fno-stack-protector -no-pie
all: UAF-0013; UAF-0013: UAF-0013.c; $(CC) $(CFLAGS) -o $@ $<
clean:; rm -f UAF-0013 *.o
