# Makefile for UAF_09
CC := gcc
CFLAGS := -Wall -O0

all: UAF_09_default

UAF_09_default: vuln.c
	  -o  $<

UAF_09_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_09_default UAF_09_no_mitigation

.PHONY: all clean
