CC ?= gcc
CFLAGS ?= -O0 -fno-stack-protector -fno-builtin

all: vuln

vuln: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f vuln vuln.exe
