# sprintf_const — FMT-C4
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/sprintf_const.exe
packed: bin/packed/sprintf_const.exe

bin/plain/sprintf_const.exe: sprintf_const.c
	$(CC) $(CFLAGS_O0) sprintf_const.c -o $@

bin/packed/sprintf_const.exe: sprintf_const.c
	$(CC) $(CFLAGS_O2) sprintf_const.c -o $@

clean:
	rm -rf bin
