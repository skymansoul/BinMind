# global_const_array — FMT-C3
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/global_const_array.exe
packed: bin/packed/global_const_array.exe

bin/plain/global_const_array.exe: global_const_array.c
	$(CC) $(CFLAGS_O0) global_const_array.c -o $@

bin/packed/global_const_array.exe: global_const_array.c
	$(CC) $(CFLAGS_O2) global_const_array.c -o $@

clean:
	rm -rf bin
