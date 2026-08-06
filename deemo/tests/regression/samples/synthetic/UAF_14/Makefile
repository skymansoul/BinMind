# Makefile for UAF_14
CC := gcc
CFLAGS := -Wall -O0

all: UAF_14_default

UAF_14_default: vuln.c
	  -o  $<

UAF_14_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_14_default UAF_14_no_mitigation

.PHONY: all clean
