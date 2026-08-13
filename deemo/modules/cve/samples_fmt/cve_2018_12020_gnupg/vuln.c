/* CVE-2018-12020 GnuPG: gets 读入缓冲后作 printf 格式串. */
#include <stdio.h>

int main(int argc, char **argv) {
    char g[256];
    if (!gets(g)) return 1;
    printf(g);
    return 0;
}
