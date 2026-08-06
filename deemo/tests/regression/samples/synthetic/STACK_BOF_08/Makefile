# Makefile for STACK_BOF_08
CC := gcc
CFLAGS := -Wall -O0

all: STACK_BOF_08_default

STACK_BOF_08_default: vuln.c
	  -o  $<

STACK_BOF_08_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f STACK_BOF_08_default STACK_BOF_08_no_mitigation

.PHONY: all clean
