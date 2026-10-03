CC=gcc
CFLAGS=-O0 -g -w
all: vuln_elf
vuln_elf: vuln.c
	$(CC) $(CFLAGS) -o vuln_elf vuln.c
clean:
	rm -f vuln_elf
# GENERIC-uaf-callback CWE-416: 回调中释放, 外层继续使用
