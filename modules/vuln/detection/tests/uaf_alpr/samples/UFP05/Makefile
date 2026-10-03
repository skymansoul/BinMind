# guarded_double_free — UFP05
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/guarded_double_free.exe
packed: bin/packed/guarded_double_free.exe

bin/plain/guarded_double_free.exe: guarded_double_free.c
	$(CC) $(CFLAGS_O0) guarded_double_free.c -o $@

bin/packed/guarded_double_free.exe: guarded_double_free.c
	$(CC) $(CFLAGS_O2) guarded_double_free.c -o $@

clean:
	rm -rf bin
