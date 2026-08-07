# sawce_arithmetic - SAWCE benchmark sample
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: sawce_arithmetic_O0 sawce_arithmetic_O2 sawce_arithmetic_Os

sawce_arithmetic_O0: sawce_arithmetic.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

sawce_arithmetic_O2: sawce_arithmetic.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

sawce_arithmetic_Os: sawce_arithmetic.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f sawce_arithmetic_O0 sawce_arithmetic_O2 sawce_arithmetic_Os
