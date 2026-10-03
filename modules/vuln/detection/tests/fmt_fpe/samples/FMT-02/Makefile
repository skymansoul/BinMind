# fprintf_fmt — FMT-02
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/fprintf_fmt.exe
packed: bin/packed/fprintf_fmt.exe

bin/plain/fprintf_fmt.exe: fprintf_fmt.c
	$(CC) $(CFLAGS_O0) fprintf_fmt.c -o $@

bin/packed/fprintf_fmt.exe: fprintf_fmt.c
	$(CC) $(CFLAGS_O2) fprintf_fmt.c -o $@

clean:
	rm -rf bin
