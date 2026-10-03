# Makefile for INT_BOF_07
CC := gcc
CFLAGS := -Wall -O0

all: INT_BOF_07_default

INT_BOF_07_default: vuln.c
	  -o  $<

INT_BOF_07_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f INT_BOF_07_default INT_BOF_07_no_mitigation

.PHONY: all clean
