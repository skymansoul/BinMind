CC=gcc
CFLAGS=-g -O0 -no-pie -fno-stack-protector
all: vuln
vuln: vuln.c
	$(CC) $(CFLAGS) -o vuln vuln.c
clean:
	rm -f vuln
