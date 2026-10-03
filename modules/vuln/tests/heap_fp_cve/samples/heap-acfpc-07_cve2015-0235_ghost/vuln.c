/* CVE-2015-0235 (GHOST gethostbyname) 堆溢出复现 — __nss_hostname_digits_dots
   中 malloc(n) 后 strncpy 写入 n 字节含终止符, off-by-one.
   简化: malloc(len) 后 strncpy(dst, src, len) 且 src 长度恰为 len,
   strncpy 强制写入 len+1 字节 (含 nul), 语言语义越界 1 字节. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t len;
    char *buf;

    if (argc < 2) {
        return 0;
    }
    len = strlen(argv[1]);
    buf = (char *)malloc(len);
    if (!buf) {
        return 1;
    }
    strncpy(buf, argv[1], len);
    printf("%s\n", buf);
    free(buf);
    return 0;
}
