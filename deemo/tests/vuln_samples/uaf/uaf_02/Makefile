CC=gcc
CFLAGS=-O0 -g -w
all: vuln_elf
vuln_elf: vuln.c
	$(CC) $(CFLAGS) -o vuln_elf vuln.c
clean:
	rm -f vuln_elf
# CVE-2022-0185 CWE-416: 内核UAF: free后通过全局变量别名使用
