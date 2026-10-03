# sawce_same_source - SAWCE benchmark sample
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: sawce_same_source_O0 sawce_same_source_O2 sawce_same_source_Os

sawce_same_source_O0: sawce_same_source.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

sawce_same_source_O2: sawce_same_source.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

sawce_same_source_Os: sawce_same_source.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f sawce_same_source_O0 sawce_same_source_O2 sawce_same_source_Os
