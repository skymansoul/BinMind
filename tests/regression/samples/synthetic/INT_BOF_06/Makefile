# Makefile for INT_BOF_06
CC := gcc
CFLAGS := -Wall -O0

all: INT_BOF_06_default

INT_BOF_06_default: vuln.c
	  -o  $<

INT_BOF_06_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f INT_BOF_06_default INT_BOF_06_no_mitigation

.PHONY: all clean
