# Makefile for UAF_03
CC := gcc
CFLAGS := -Wall -O0

all: UAF_03_default

UAF_03_default: vuln.c
	  -o  $<

UAF_03_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_03_default UAF_03_no_mitigation

.PHONY: all clean
