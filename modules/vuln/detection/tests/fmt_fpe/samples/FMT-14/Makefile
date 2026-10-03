# argv_fmt — FMT-14
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/argv_fmt.exe
packed: bin/packed/argv_fmt.exe

bin/plain/argv_fmt.exe: argv_fmt.c
	$(CC) $(CFLAGS_O0) argv_fmt.c -o $@

bin/packed/argv_fmt.exe: argv_fmt.c
	$(CC) $(CFLAGS_O2) argv_fmt.c -o $@

clean:
	rm -rf bin
