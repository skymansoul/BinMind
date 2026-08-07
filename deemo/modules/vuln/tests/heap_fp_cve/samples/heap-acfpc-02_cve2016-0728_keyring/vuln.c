/* CVE-2016-0728 (Linux keyring) 堆溢出复现 — join_session_keyring 中
   key 描述符复制时, 分配 128 字节但 memcpy 写入 strlen+len+1 可超界.
   简化: malloc(128) + memcpy(buf, desc, 260) 常量越界, 走 CONFIRM. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_DESC_LEN 256

int main(void) {
    char desc[KEY_DESC_LEN + 8];
    char *buf;
    size_t n;

    memset(desc, 'A', KEY_DESC_LEN);
    desc[KEY_DESC_LEN] = 0;
    buf = (char *)malloc(128);
    if (!buf) {
        return 1;
    }
    n = strlen(desc) + 4;
    memcpy(buf, desc, n);
    printf("%s\n", buf);
    free(buf);
    return 0;
}
