# Makefile for UAF_06
CC := gcc
CFLAGS := -Wall -O0

all: UAF_06_default

UAF_06_default: vuln.c
	  -o  $<

UAF_06_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_06_default UAF_06_no_mitigation

.PHONY: all clean
