# Makefile for INT_BOF_05
CC := gcc
CFLAGS := -Wall -O0

all: INT_BOF_05_default

INT_BOF_05_default: vuln.c
	  -o  $<

INT_BOF_05_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f INT_BOF_05_default INT_BOF_05_no_mitigation

.PHONY: all clean
