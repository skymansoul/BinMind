# Makefile for UAF_07
CC := gcc
CFLAGS := -Wall -O0

all: UAF_07_default

UAF_07_default: vuln.c
	  -o  $<

UAF_07_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_07_default UAF_07_no_mitigation

.PHONY: all clean
