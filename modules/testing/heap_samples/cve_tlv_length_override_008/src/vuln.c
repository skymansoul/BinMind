/* TLV: allocate per declared_len, copy actual_len > declared_len */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct tlv { unsigned short type, length; unsigned char value[]; };
int main(int argc, char **argv) {
    unsigned short dlen = argc > 1 ? (unsigned short)atoi(argv[1]) : 10;
    const char *actual = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFFF";
    size_t alen = strlen(actual);
    struct tlv *p = (struct tlv *)malloc(sizeof(*p) + dlen);
    if (!p) return 1;
    p->type = 1; p->length = dlen;
    memcpy(p->value, actual, alen);  /* BUG: alen > dlen */
    printf("[*] type=%u dlen=%u alen=%zu\n", p->type, p->length, alen);
    free(p);
    return 0;
}
