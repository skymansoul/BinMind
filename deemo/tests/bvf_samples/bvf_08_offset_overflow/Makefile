CC=gcc
CFLAGS=-w -O0 -g

target: bvf_08_offset_overflow.elf

bvf_08_offset_overflow.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_08_offset_overflow.elf

