# sawce_loop_accumulate - SAWCE benchmark sample
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: sawce_loop_accumulate_O0 sawce_loop_accumulate_O2 sawce_loop_accumulate_Os

sawce_loop_accumulate_O0: sawce_loop_accumulate.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

sawce_loop_accumulate_O2: sawce_loop_accumulate.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

sawce_loop_accumulate_Os: sawce_loop_accumulate.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f sawce_loop_accumulate_O0 sawce_loop_accumulate_O2 sawce_loop_accumulate_Os
