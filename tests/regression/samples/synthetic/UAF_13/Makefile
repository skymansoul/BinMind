# Makefile for UAF_13
CC := gcc
CFLAGS := -Wall -O0

all: UAF_13_default

UAF_13_default: vuln.c
	  -o  $<

UAF_13_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_13_default UAF_13_no_mitigation

.PHONY: all clean
