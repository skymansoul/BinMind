# direct_const — FMT-C1
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/direct_const.exe
packed: bin/packed/direct_const.exe

bin/plain/direct_const.exe: direct_const.c
	$(CC) $(CFLAGS_O0) direct_const.c -o $@

bin/packed/direct_const.exe: direct_const.c
	$(CC) $(CFLAGS_O2) direct_const.c -o $@

clean:
	rm -rf bin
