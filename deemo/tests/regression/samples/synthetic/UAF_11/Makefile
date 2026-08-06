# Makefile for UAF_11
CC := gcc
CFLAGS := -Wall -O0

all: UAF_11_default

UAF_11_default: vuln.c
	  -o  $<

UAF_11_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_11_default UAF_11_no_mitigation

.PHONY: all clean
