# fprintf_stdout_fmt — FMT-11
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/fprintf_stdout_fmt.exe
packed: bin/packed/fprintf_stdout_fmt.exe

bin/plain/fprintf_stdout_fmt.exe: fprintf_stdout_fmt.c
	$(CC) $(CFLAGS_O0) fprintf_stdout_fmt.c -o $@

bin/packed/fprintf_stdout_fmt.exe: fprintf_stdout_fmt.c
	$(CC) $(CFLAGS_O2) fprintf_stdout_fmt.c -o $@

clean:
	rm -rf bin
