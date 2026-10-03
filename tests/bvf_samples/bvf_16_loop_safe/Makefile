CC=gcc
CFLAGS=-w -O0 -g

target: bvf_16_loop_safe.elf

bvf_16_loop_safe.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_16_loop_safe.elf

