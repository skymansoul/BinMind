CC=gcc
CFLAGS=-w -O0 -g

target: bvf_03_arith_safe.elf

bvf_03_arith_safe.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_03_arith_safe.elf

