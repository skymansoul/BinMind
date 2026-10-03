CC=gcc
CFLAGS=-w -O0 -g

target: bvf_04_arith_overflow.elf

bvf_04_arith_overflow.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_04_arith_overflow.elf

