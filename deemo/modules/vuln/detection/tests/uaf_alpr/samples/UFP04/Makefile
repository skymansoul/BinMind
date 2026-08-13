# null_rebind — UFP04
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/null_rebind.exe
packed: bin/packed/null_rebind.exe

bin/plain/null_rebind.exe: null_rebind.c
	$(CC) $(CFLAGS_O0) null_rebind.c -o $@

bin/packed/null_rebind.exe: null_rebind.c
	$(CC) $(CFLAGS_O2) null_rebind.c -o $@

clean:
	rm -rf bin
