CC = gcc
CFLAGS = -O0 -g -no-pie -fno-stack-protector

SAMPLES = $(wildcard lsp_*/vuln.c)
BINS = $(SAMPLES:.c=.exe)

all: $(BINS)

%.exe: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f lsp_*/vuln.exe

.PHONY: all clean
