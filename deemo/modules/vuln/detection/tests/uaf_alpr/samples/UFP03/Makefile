# use_before_free — UFP03
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/use_before_free.exe
packed: bin/packed/use_before_free.exe

bin/plain/use_before_free.exe: use_before_free.c
	$(CC) $(CFLAGS_O0) use_before_free.c -o $@

bin/packed/use_before_free.exe: use_before_free.c
	$(CC) $(CFLAGS_O2) use_before_free.c -o $@

clean:
	rm -rf bin
