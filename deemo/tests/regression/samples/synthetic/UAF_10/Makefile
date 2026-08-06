# Makefile for UAF_10
CC := gcc
CFLAGS := -Wall -O0

all: UAF_10_default

UAF_10_default: vuln.c
	  -o  $<

UAF_10_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_10_default UAF_10_no_mitigation

.PHONY: all clean
