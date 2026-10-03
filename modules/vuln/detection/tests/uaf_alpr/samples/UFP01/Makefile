# rebind_after_free — UFP01
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/rebind_after_free.exe
packed: bin/packed/rebind_after_free.exe

bin/plain/rebind_after_free.exe: rebind_after_free.c
	$(CC) $(CFLAGS_O0) rebind_after_free.c -o $@

bin/packed/rebind_after_free.exe: rebind_after_free.c
	$(CC) $(CFLAGS_O2) rebind_after_free.c -o $@

clean:
	rm -rf bin
