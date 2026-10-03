CC=gcc
CFLAGS=-w -O0 -g

target: bvf_06_no_shared_unrelated.elf

bvf_06_no_shared_unrelated.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_06_no_shared_unrelated.elf

