# sprintf_fmt — FMT-03
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/sprintf_fmt.exe
packed: bin/packed/sprintf_fmt.exe

bin/plain/sprintf_fmt.exe: sprintf_fmt.c
	$(CC) $(CFLAGS_O0) sprintf_fmt.c -o $@

bin/packed/sprintf_fmt.exe: sprintf_fmt.c
	$(CC) $(CFLAGS_O2) sprintf_fmt.c -o $@

clean:
	rm -rf bin
