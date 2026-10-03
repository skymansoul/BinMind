/* CVE-2019-9670 — Zimbra Collaboration integer overflow
   Type: integer_overflow   gcc -O0 zimbra_int_overflow.c -o zimbra_int_overflow
   Zimbra mailboxd XML parser had integer overflow in array size calc. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_xml_items(int item_count, const char *data) {
    int alloc_size = item_count * 48 + 16;
    /* BUG: if item_count > 0x05555555, alloc_size overflows to small value */
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return;
    memcpy(buf, data, (unsigned int)(item_count * 48));
    printf("Parsed %d items, %d bytes\n", item_count, alloc_size);
    free(buf);
}
int main() {
    parse_xml_items(0x05555556, "data");
    return 0;
}
