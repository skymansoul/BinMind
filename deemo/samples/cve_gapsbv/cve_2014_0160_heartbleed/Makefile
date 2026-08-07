CC = gcc
CFLAGS = -Wall -O0 -g -no-pie

all: vuln.exe

vuln.exe: vuln.c
	$(CC) $(CFLAGS) -o vuln.exe vuln.c

clean:
	rm -f vuln.exe

.PHONY: all clean
