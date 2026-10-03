# reassign_fmt — FMT-10
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/reassign_fmt.exe
packed: bin/packed/reassign_fmt.exe

bin/plain/reassign_fmt.exe: reassign_fmt.c
	$(CC) $(CFLAGS_O0) reassign_fmt.c -o $@

bin/packed/reassign_fmt.exe: reassign_fmt.c
	$(CC) $(CFLAGS_O2) reassign_fmt.c -o $@

clean:
	rm -rf bin
