/* CVE-2017-17506 — gdk-pixbuf: header length vs line buffer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *parse_image(const unsigned char *hdr, size_t hdr_len) {
    /* 行缓冲按固定宽度分配, 复制长度来自头部 */
    void *line = malloc(0x100);
    if (!line) return NULL;
    memcpy(line, hdr, hdr_len);         /* BUG: hdr_len up to 0xffff */
    return line;
}
int main(int argc, char **argv) {
    size_t len = argc > 1 ? (size_t)atoi(argv[1]) : 0x300;
    unsigned char hdr[0x400];
    memset(hdr, 'E', sizeof(hdr));
    void *p = parse_image(hdr, len);
    if (p) { printf("[*] parsed\n"); free(p); }
    return 0;
}
