CC=gcc
CFLAGS=-O0 -g -w
all: vuln_elf
vuln_elf: vuln.c
	$(CC) $(CFLAGS) -o vuln_elf vuln.c
clean:
	rm -f vuln_elf
# GENERIC-fmt-snprintf-safe SAFE: snprintf正确边界检查——安全模式
