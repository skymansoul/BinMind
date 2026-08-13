# free_error_branch — UFP02
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/free_error_branch.exe
packed: bin/packed/free_error_branch.exe

bin/plain/free_error_branch.exe: free_error_branch.c
	$(CC) $(CFLAGS_O0) free_error_branch.c -o $@

bin/packed/free_error_branch.exe: free_error_branch.c
	$(CC) $(CFLAGS_O2) free_error_branch.c -o $@

clean:
	rm -rf bin
