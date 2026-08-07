CC=gcc
CFLAGS=-w -O0 -g

target: bvf_14_realloc_noexpand_overflow.elf

bvf_14_realloc_noexpand_overflow.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_14_realloc_noexpand_overflow.elf

