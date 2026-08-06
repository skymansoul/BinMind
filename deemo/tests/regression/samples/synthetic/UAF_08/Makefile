# Makefile for UAF_08
CC := gcc
CFLAGS := -Wall -O0

all: UAF_08_default

UAF_08_default: vuln.c
	  -o  $<

UAF_08_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_08_default UAF_08_no_mitigation

.PHONY: all clean
