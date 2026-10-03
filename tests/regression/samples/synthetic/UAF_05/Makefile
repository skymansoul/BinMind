# Makefile for UAF_05
CC := gcc
CFLAGS := -Wall -O0

all: UAF_05_default

UAF_05_default: vuln.c
	  -o  $<

UAF_05_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f UAF_05_default UAF_05_no_mitigation

.PHONY: all clean
