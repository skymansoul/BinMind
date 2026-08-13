# fgets_fmt — FMT-12
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/fgets_fmt.exe
packed: bin/packed/fgets_fmt.exe

bin/plain/fgets_fmt.exe: fgets_fmt.c
	$(CC) $(CFLAGS_O0) fgets_fmt.c -o $@

bin/packed/fgets_fmt.exe: fgets_fmt.c
	$(CC) $(CFLAGS_O2) fgets_fmt.c -o $@

clean:
	rm -rf bin
