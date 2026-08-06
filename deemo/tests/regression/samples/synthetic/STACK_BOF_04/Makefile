# Makefile for STACK_BOF_04
CC := gcc
CFLAGS := -Wall -O0

all: STACK_BOF_04_default

STACK_BOF_04_default: vuln.c
	  -o  $<

STACK_BOF_04_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f STACK_BOF_04_default STACK_BOF_04_no_mitigation

.PHONY: all clean
