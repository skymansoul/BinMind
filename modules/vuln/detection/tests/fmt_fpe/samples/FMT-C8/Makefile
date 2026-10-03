# fprintf_const — FMT-C8
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/fprintf_const.exe
packed: bin/packed/fprintf_const.exe

bin/plain/fprintf_const.exe: fprintf_const.c
	$(CC) $(CFLAGS_O0) fprintf_const.c -o $@

bin/packed/fprintf_const.exe: fprintf_const.c
	$(CC) $(CFLAGS_O2) fprintf_const.c -o $@

clean:
	rm -rf bin
