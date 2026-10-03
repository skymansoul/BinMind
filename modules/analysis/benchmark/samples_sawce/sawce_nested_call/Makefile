# sawce_nested_call - SAWCE benchmark sample
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: sawce_nested_call_O0 sawce_nested_call_O2 sawce_nested_call_Os

sawce_nested_call_O0: sawce_nested_call.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

sawce_nested_call_O2: sawce_nested_call.c
	$(CC) $(CFLAGS) -O2 -o $@ $<

sawce_nested_call_Os: sawce_nested_call.c
	$(CC) $(CFLAGS) -Os -o $@ $<

clean:
	rm -f sawce_nested_call_O0 sawce_nested_call_O2 sawce_nested_call_Os
