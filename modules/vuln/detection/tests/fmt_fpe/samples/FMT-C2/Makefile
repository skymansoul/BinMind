# local_var_const — FMT-C2
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/local_var_const.exe
packed: bin/packed/local_var_const.exe

bin/plain/local_var_const.exe: local_var_const.c
	$(CC) $(CFLAGS_O0) local_var_const.c -o $@

bin/packed/local_var_const.exe: local_var_const.c
	$(CC) $(CFLAGS_O2) local_var_const.c -o $@

clean:
	rm -rf bin
