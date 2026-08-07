CC=gcc
CFLAGS=-w -O0 -g

target: bvf_18_struct_field_overflow.elf

bvf_18_struct_field_overflow.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_18_struct_field_overflow.elf

