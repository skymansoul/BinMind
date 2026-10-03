/* CVE-2018-14634: Linux kernel create_elf_tables heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void build_elf_tables(char **envp, int envc, size_t total_size) {
    /* BUG: total_size 可能因整数溢出而变得很小 */
    if (total_size > 0x100000) total_size = 0x100000;
    char *buf = (char *)malloc(total_size + 4096);
    if (!buf) return;
    size_t pos = 0;
    for (int i = 0; i < envc && pos < total_size + 8192; i++) {
        size_t slen = strlen(envp[i]) + 1;
        memcpy(buf + pos, envp[i], slen);  /* BUG: may write past total_size */
        pos += slen;
    }
    buf[pos] = '\0';
    free(buf);
}

int main(int argc, char **argv) {
    char *env[] = { "PATH=/bin", "HOME=/root", "USER=admin", "LANG=en_US.UTF-8",
                     "SHELL=/bin/bash", NULL };
    int envc = 5;
    size_t total = 0;
    for (int i = 0; i < envc; i++) total += strlen(env[i]) + 1;
    if (argc >= 2) total = (size_t)atol(argv[1]);
    build_elf_tables(env, envc, total);
    printf("done\n");
    return 0;
}
