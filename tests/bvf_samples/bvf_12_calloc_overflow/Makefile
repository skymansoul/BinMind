CC=gcc
CFLAGS=-w -O0 -g

target: bvf_12_calloc_overflow.elf

bvf_12_calloc_overflow.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_12_calloc_overflow.elf

