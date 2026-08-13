# no_args_const — FMT-C5
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/no_args_const.exe
packed: bin/packed/no_args_const.exe

bin/plain/no_args_const.exe: no_args_const.c
	$(CC) $(CFLAGS_O0) no_args_const.c -o $@

bin/packed/no_args_const.exe: no_args_const.c
	$(CC) $(CFLAGS_O2) no_args_const.c -o $@

clean:
	rm -rf bin
