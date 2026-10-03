# Makefile for HEAP_BOF_08
CC := gcc
CFLAGS := -Wall -O0

all: HEAP_BOF_08_default

HEAP_BOF_08_default: vuln.c
	  -o  $<

HEAP_BOF_08_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f HEAP_BOF_08_default HEAP_BOF_08_no_mitigation

.PHONY: all clean
