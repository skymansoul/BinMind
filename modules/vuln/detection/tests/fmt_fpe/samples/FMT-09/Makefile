# vprintf_fmt — FMT-09
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/vprintf_fmt.exe
packed: bin/packed/vprintf_fmt.exe

bin/plain/vprintf_fmt.exe: vprintf_fmt.c
	$(CC) $(CFLAGS_O0) vprintf_fmt.c -o $@

bin/packed/vprintf_fmt.exe: vprintf_fmt.c
	$(CC) $(CFLAGS_O2) vprintf_fmt.c -o $@

clean:
	rm -rf bin
