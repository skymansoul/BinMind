# Makefile for FMT_STR_15
CC := gcc
CFLAGS := -Wall -O0

all: FMT_STR_15_default

FMT_STR_15_default: vuln.c
	  -o  $<

FMT_STR_15_no_mitigation: vuln.c
	  -fno-stack-protector -z execstack -o  $<

clean:
	rm -f FMT_STR_15_default FMT_STR_15_no_mitigation

.PHONY: all clean
