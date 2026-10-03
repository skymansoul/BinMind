# microsoft_fmt — FMT-01
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/microsoft_fmt.exe
packed: bin/packed/microsoft_fmt.exe

bin/plain/microsoft_fmt.exe: microsoft_fmt.c
	$(CC) $(CFLAGS_O0) microsoft_fmt.c -o $@

bin/packed/microsoft_fmt.exe: microsoft_fmt.c
	$(CC) $(CFLAGS_O2) microsoft_fmt.c -o $@

clean:
	rm -rf bin
