CC=gcc
CFLAGS=-std=c99
all: vuln_o0 vuln_o2
vuln_o0: vuln.c ;   -O0 -g -o vuln_o0 vuln.c
vuln_o2: vuln.c ;   -O2 -o vuln_o2 vuln.c
clean: ; rm -f vuln_o0 vuln_o2
