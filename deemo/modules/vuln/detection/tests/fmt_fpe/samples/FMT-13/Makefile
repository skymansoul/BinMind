# env_fmt — FMT-13
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/env_fmt.exe
packed: bin/packed/env_fmt.exe

bin/plain/env_fmt.exe: env_fmt.c
	$(CC) $(CFLAGS_O0) env_fmt.c -o $@

bin/packed/env_fmt.exe: env_fmt.c
	$(CC) $(CFLAGS_O2) env_fmt.c -o $@

clean:
	rm -rf bin
