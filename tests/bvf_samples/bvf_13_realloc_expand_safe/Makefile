CC=gcc
CFLAGS=-w -O0 -g

target: bvf_13_realloc_expand_safe.elf

bvf_13_realloc_expand_safe.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_13_realloc_expand_safe.elf

