# sawce_derived_boundary - SAWCE benchmark sample
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: sawce_derived_boundary_O0 sawce_derived_boundary_O2 sawce_derived_boundary_Os

sawce_derived_boundary_O0: sawce_derived_boundary.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

sawce_derived_boundary_O2: sawce_derived_boundary.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

sawce_derived_boundary_Os: sawce_derived_boundary.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f sawce_derived_boundary_O0 sawce_derived_boundary_O2 sawce_derived_boundary_Os
