# snprintf_const — FMT-C7
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/snprintf_const.exe
packed: bin/packed/snprintf_const.exe

bin/plain/snprintf_const.exe: snprintf_const.c
	$(CC) $(CFLAGS_O0) snprintf_const.c -o $@

bin/packed/snprintf_const.exe: snprintf_const.c
	$(CC) $(CFLAGS_O2) snprintf_const.c -o $@

clean:
	rm -rf bin
