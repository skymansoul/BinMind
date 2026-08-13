# realloc_rebind — UFP08
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/realloc_rebind.exe
packed: bin/packed/realloc_rebind.exe

bin/plain/realloc_rebind.exe: realloc_rebind.c
	$(CC) $(CFLAGS_O0) realloc_rebind.c -o $@

bin/packed/realloc_rebind.exe: realloc_rebind.c
	$(CC) $(CFLAGS_O2) realloc_rebind.c -o $@

clean:
	rm -rf bin
