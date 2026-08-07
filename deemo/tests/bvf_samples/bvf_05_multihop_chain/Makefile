CC=gcc
CFLAGS=-w -O0 -g

target: bvf_05_multihop_chain.elf

bvf_05_multihop_chain.elf: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f bvf_05_multihop_chain.elf

