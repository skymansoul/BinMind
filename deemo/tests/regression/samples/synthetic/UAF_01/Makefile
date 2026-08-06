# Makefile for UAF_01
CC := gcc
CFLAGS := -Wall -O0

all: UAF_01_default

UAF_01_default: vuln.c
	  -o  $<

UAF_01_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_01_default UAF_01_no_mitigation

.PHONY: all clean
