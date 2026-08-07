CC ?= gcc
CFLAGS = -Wall -O0 -g -fno-builtin -fno-stack-protector -no-pie

vuln.exe: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

vuln.asm: vuln.exe
	objdump -d -M intel vuln.exe > vuln.asm

all: vuln.exe vuln.asm

clean:
	rm -f vuln.exe vuln.asm vuln.o
