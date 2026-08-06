# Makefile for UAF_12
CC := gcc
CFLAGS := -Wall -O0

all: UAF_12_default

UAF_12_default: vuln.c
	  -o  $<

UAF_12_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_12_default UAF_12_no_mitigation

.PHONY: all clean
