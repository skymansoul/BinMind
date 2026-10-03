# syslog_fmt — FMT-15
CC ?= gcc
CFLAGS_O0 := -O0 -fno-pic -fno-stack-protector
CFLAGS_O2 := -O2 -fno-pic -fno-stack-protector -fno-tree-dce -fno-tree-dse -fno-inline -fno-builtin

all: plain packed
plain: bin/plain/syslog_fmt.exe
packed: bin/packed/syslog_fmt.exe

bin/plain/syslog_fmt.exe: syslog_fmt.c
	$(CC) $(CFLAGS_O0) syslog_fmt.c -o $@

bin/packed/syslog_fmt.exe: syslog_fmt.c
	$(CC) $(CFLAGS_O2) syslog_fmt.c -o $@

clean:
	rm -rf bin
