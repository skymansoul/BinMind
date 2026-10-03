# Makefile for UAF_15
CC := gcc
CFLAGS := -Wall -O0

all: UAF_15_default

UAF_15_default: vuln.c
	  -o  $<

UAF_15_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_15_default UAF_15_no_mitigation

.PHONY: all clean
