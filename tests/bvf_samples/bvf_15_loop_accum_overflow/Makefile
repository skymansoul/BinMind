CC=gcc
CFLAGS=-w -O0 -g

target: bvf_15_loop_accum_overflow.elf

bvf_15_loop_accum_overflow.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_15_loop_accum_overflow.elf

