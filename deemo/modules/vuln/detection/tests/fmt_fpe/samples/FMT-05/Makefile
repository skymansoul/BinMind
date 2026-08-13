# gets_fmt — FMT-05
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/gets_fmt.exe
packed: bin/packed/gets_fmt.exe

bin/plain/gets_fmt.exe: gets_fmt.c
	$(CC) $(CFLAGS_O0) gets_fmt.c -o $@

bin/packed/gets_fmt.exe: gets_fmt.c
	$(CC) $(CFLAGS_O2) gets_fmt.c -o $@

clean:
	rm -rf bin
