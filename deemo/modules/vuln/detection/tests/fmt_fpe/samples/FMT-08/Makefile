# strcpy_fmt — FMT-08
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/strcpy_fmt.exe
packed: bin/packed/strcpy_fmt.exe

bin/plain/strcpy_fmt.exe: strcpy_fmt.c
	$(CC) $(CFLAGS_O0) strcpy_fmt.c -o $@

bin/packed/strcpy_fmt.exe: strcpy_fmt.c
	$(CC) $(CFLAGS_O2) strcpy_fmt.c -o $@

clean:
	rm -rf bin
