# helper_const — FMT-C6
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/helper_const.exe
packed: bin/packed/helper_const.exe

bin/plain/helper_const.exe: helper_const.c
	$(CC) $(CFLAGS_O0) helper_const.c -o $@

bin/packed/helper_const.exe: helper_const.c
	$(CC) $(CFLAGS_O2) helper_const.c -o $@

clean:
	rm -rf bin
