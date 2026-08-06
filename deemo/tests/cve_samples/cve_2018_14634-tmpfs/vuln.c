/* CVE-2018-14634: Linux tmpfs 整数溢出→堆溢出 —— 简化 */
#include <stdlib.h>
#include <string.h>
void tmpfs_xattr_set(char *value, unsigned int kvlen) {
    unsigned int sz = kvlen + 24;
    /* BUG: kvlen=0xFFFFFFF0 → sz=0x08 (回绕), 但后续 memcpy 写入 kvlen 字节 */
    char *buf = malloc(sz);
    memcpy(buf, value, kvlen);
    free(buf);
}
int main() { tmpfs_xattr_set("AAAA", 0xFFFFFFF0); return 0; }
