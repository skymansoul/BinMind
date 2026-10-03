CC=gcc
CFLAGS=-g -O0 -fno-stack-protector

all: vuln

vuln: vuln.c
	$ $(CFLAGS) -o vuln vuln.c

clean:
	rm -f vuln
