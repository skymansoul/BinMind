CC=gcc
CFLAGS=-w -O0 -g

target: bvf_10_guard_capped_safe.elf

bvf_10_guard_capped_safe.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_10_guard_capped_safe.elf

