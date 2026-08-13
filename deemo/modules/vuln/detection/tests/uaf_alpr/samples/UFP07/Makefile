# alias_live — UFP07
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/alias_live.exe
packed: bin/packed/alias_live.exe

bin/plain/alias_live.exe: alias_live.c
	$(CC) $(CFLAGS_O0) alias_live.c -o $@

bin/packed/alias_live.exe: alias_live.c
	$(CC) $(CFLAGS_O2) alias_live.c -o $@

clean:
	rm -rf bin
