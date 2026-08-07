CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector

all: vuln.exe

vuln.exe: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f vuln.exe
