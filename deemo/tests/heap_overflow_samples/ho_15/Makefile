CC=gcc
CFLAGS=-O0 -g -w
all: vuln_elf
vuln_elf: vuln.c
	$(CC) $(CFLAGS) -o vuln_elf vuln.c
clean:
	rm -f vuln_elf
# SAFE-correct-check SAFE: 正确边界检查——负面测试，不应检出
