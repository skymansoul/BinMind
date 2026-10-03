CC=gcc
CFLAGS=-w -O0 -g

target: bvf_17_struct_field_safe.elf

bvf_17_struct_field_safe.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_17_struct_field_safe.elf

