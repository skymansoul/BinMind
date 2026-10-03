CC = gcc
CFLAGS = -O0 -g -no-pie -fno-stack-protector -c

SAMPLES = $(wildcard pcbvf_*/vuln.c)
OBJS = $(SAMPLES:.c=.o)

all: $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pcbvf_*/vuln.o

.PHONY: all clean
