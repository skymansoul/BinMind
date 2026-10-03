# Makefile for UAF_04
CC := gcc
CFLAGS := -Wall -O0

all: UAF_04_default

UAF_04_default: vuln.c
	  -o  $<

UAF_04_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_04_default UAF_04_no_mitigation

.PHONY: all clean
