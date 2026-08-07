CC=gcc
CFLAGS=-w -O0 -g

target: bvf_02_shared_var_overflow.elf

bvf_02_shared_var_overflow.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_02_shared_var_overflow.elf

