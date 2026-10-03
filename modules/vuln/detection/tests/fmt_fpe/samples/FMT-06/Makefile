# param_fmt — FMT-06
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/param_fmt.exe
packed: bin/packed/param_fmt.exe

bin/plain/param_fmt.exe: param_fmt.c
	$(CC) $(CFLAGS_O0) param_fmt.c -o $@

bin/packed/param_fmt.exe: param_fmt.c
	$(CC) $(CFLAGS_O2) param_fmt.c -o $@

clean:
	rm -rf bin
