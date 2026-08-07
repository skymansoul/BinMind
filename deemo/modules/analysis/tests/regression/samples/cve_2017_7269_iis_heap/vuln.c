/* CVE-2017-7269: IIS WebDAV heap overflow pattern */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_if_header(const char *if_header, size_t hdr_len) {
    size_t buf_sz = hdr_len + 256;
    if (buf_sz > 65536) buf_sz = 65536;
    char *buf = (char *)malloc(buf_sz);
    if (!buf) return;
    /* BUG: 写入时未考虑hdr_len可能等于buf_sz, 加上null terminator超出 */
    memcpy(buf, if_header, hdr_len);
    buf[hdr_len + 128] = '\0';  /* overflow: writes beyond allocated region */
    free(buf);
}

int main(int argc, char **argv) {
    char input[1024]; memset(input, 'X', 1024);
    if (argc >= 2) strncpy(input, argv[1], 1023);
    parse_if_header(input, strlen(input));
    printf("done\n");
    return 0;
}
