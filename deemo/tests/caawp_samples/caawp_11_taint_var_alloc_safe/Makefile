CC=gcc
CFLAGS=-g -O0 -fsanitize=address

all: vuln

vuln: vuln.c
	$(CC) $(CFLAGS) -o vuln vuln.c

clean:
	rm -f vuln
