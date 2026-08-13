# read_fmt — FMT-04
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/read_fmt.exe
packed: bin/packed/read_fmt.exe

bin/plain/read_fmt.exe: read_fmt.c
	$(CC) $(CFLAGS_O0) read_fmt.c -o $@

bin/packed/read_fmt.exe: read_fmt.c
	$(CC) $(CFLAGS_O2) read_fmt.c -o $@

clean:
	rm -rf bin
