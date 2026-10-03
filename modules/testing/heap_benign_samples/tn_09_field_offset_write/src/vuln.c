#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct hdr { unsigned len; unsigned flags; unsigned char body[0x100]; };
int main(void) {
    struct hdr *h = (struct hdr *)malloc(sizeof(struct hdr));
    if (!h) return 1;
    h->len = 0x80;
    h->flags = 0;
    memset(h->body, 0, 0x80);         /* 偏移 8, 写入 0x80, 总量在对象内 */
    printf("[*] len=%u\n", h->len);
    free(h);
    return 0;
}
