CC = gcc
CFLAGS = -O0 -g

all: vuln

vuln: vuln.c
	$(CC) $(CFLAGS) -o vuln vuln.c

run: vuln
	./vuln

clean:
	rm -f vuln
