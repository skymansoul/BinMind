# Makefile for INT_BOF_11
CC := gcc
CFLAGS := -Wall -O0

all: INT_BOF_11_default

INT_BOF_11_default: vuln.c
	  -o  $<

INT_BOF_11_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f INT_BOF_11_default INT_BOF_11_no_mitigation

.PHONY: all clean
