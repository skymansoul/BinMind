CC=gcc
CFLAGS=-w -O0 -g

target: bvf_11_calloc_safe.elf

bvf_11_calloc_safe.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_11_calloc_safe.elf

