CC=gcc
CFLAGS=-w -O0 -g

target: bvf_09_taint_unbounded.elf

bvf_09_taint_unbounded.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_09_taint_unbounded.elf

