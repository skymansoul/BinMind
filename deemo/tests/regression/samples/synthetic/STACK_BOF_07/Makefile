# Makefile for STACK_BOF_07
CC := gcc
CFLAGS := -Wall -O0

all: STACK_BOF_07_default

STACK_BOF_07_default: vuln.c
	  -o  $<

STACK_BOF_07_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f STACK_BOF_07_default STACK_BOF_07_no_mitigation

.PHONY: all clean
