# Makefile for UAF_02
CC := gcc
CFLAGS := -Wall -O0

all: UAF_02_default

UAF_02_default: vuln.c
	  -o  $<

UAF_02_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_02_default UAF_02_no_mitigation

.PHONY: all clean
