# stack_other_object — UFP06
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/stack_other_object.exe
packed: bin/packed/stack_other_object.exe

bin/plain/stack_other_object.exe: stack_other_object.c
	$(CC) $(CFLAGS_O0) stack_other_object.c -o $@

bin/packed/stack_other_object.exe: stack_other_object.c
	$(CC) $(CFLAGS_O2) stack_other_object.c -o $@

clean:
	rm -rf bin
