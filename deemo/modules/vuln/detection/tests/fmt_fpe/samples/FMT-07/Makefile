# snprintf_fmt — FMT-07
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/snprintf_fmt.exe
packed: bin/packed/snprintf_fmt.exe

bin/plain/snprintf_fmt.exe: snprintf_fmt.c
	$(CC) $(CFLAGS_O0) snprintf_fmt.c -o $@

bin/packed/snprintf_fmt.exe: snprintf_fmt.c
	$(CC) $(CFLAGS_O2) snprintf_fmt.c -o $@

clean:
	rm -rf bin
