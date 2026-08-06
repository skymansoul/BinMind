/* CVE-2018-14634 — Linux kernel create_elf_tables integer overflow
   Type: integer_overflow   gcc -O0 linux_int_overflow.c -o linux_int_overflow
   create_elf_tables() had unchecked multiplication leading to heap overflow. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void setup_elf_tables(int argc, int envc) {
    int size = (argc + envc + 2) * 8;
    /* BUG: if argc+envc > 0x1FFFFFFF, size overflows */
    char *stack = (char *)malloc(size);
    if (!stack) return;
    memset(stack, 0, (unsigned int)((argc + envc + 2) * 8));
    printf("ELF auxv: %d bytes\n", size);
    free(stack);
}
int main() {
    setup_elf_tables(0x10000000, 0x10000000);
    return 0;
}
