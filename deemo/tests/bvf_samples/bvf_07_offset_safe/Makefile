CC=gcc
CFLAGS=-w -O0 -g

target: bvf_07_offset_safe.elf

bvf_07_offset_safe.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_07_offset_safe.elf

